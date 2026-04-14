using System.Text.Json;

namespace Need4AdminLight.Web.Services;

/// <summary>
/// Basic JWT checks for a Microsoft Graph access token before establishing a server session.
/// Cryptographic signature is not verified locally; Microsoft Graph validates the token when we call <c>/me</c>.
/// </summary>
public static class GraphAccessTokenGuard
{
    private const string GraphAudienceUrl = "https://graph.microsoft.com";
    private const string GraphAudienceGuid = "00000003-0000-0000-c000-000000000000";

    /// <summary>HTTPS hosts Microsoft uses for Entra access-token <c>iss</c> (v1/v2, commercial + common sovereign clouds).</summary>
    private static readonly HashSet<string> TrustedIssuerHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "login.microsoftonline.com",
        "login.microsoftonline.us",
        "login.microsoftonline.de",
        "login.microsoftonline.cn",
        "login.partner.microsoftonline.cn",
        "sts.windows.net"
    };

    public static void ValidateOrThrow(string accessToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw new ArgumentException("Access token is empty.", nameof(accessToken));
        }

        var parts = accessToken.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3)
        {
            throw new InvalidOperationException("Token is not a JWT.");
        }

        byte[] payloadBytes;
        try
        {
            payloadBytes = Base64UrlDecode(parts[1]);
        }
        catch
        {
            throw new InvalidOperationException("Invalid token payload encoding.");
        }

        using var doc = JsonDocument.Parse(payloadBytes);
        var root = doc.RootElement;

        if (!root.TryGetProperty("exp", out var expEl) || expEl.ValueKind != JsonValueKind.Number ||
            !expEl.TryGetInt64(out var expUnix))
        {
            throw new InvalidOperationException("Token missing exp.");
        }

        var exp = DateTimeOffset.FromUnixTimeSeconds(expUnix);
        if (exp <= DateTimeOffset.UtcNow.AddMinutes(-2))
        {
            throw new InvalidOperationException("Token expired.");
        }

        if (!TryGetAudiences(root, out var audiences) || !audiences.Exists(IsGraphAccessTokenAudience))
        {
            throw new InvalidOperationException("Token is not for Microsoft Graph.");
        }

        if (!root.TryGetProperty("iss", out var issEl) || issEl.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException("Token missing iss.");
        }

        var iss = issEl.GetString();
        if (string.IsNullOrWhiteSpace(iss) || !IsTrustedEntraIssuer(iss))
        {
            throw new InvalidOperationException("Invalid token issuer.");
        }
    }

    private static bool IsGraphAccessTokenAudience(string? aud)
    {
        if (string.IsNullOrEmpty(aud))
        {
            return false;
        }

        aud = aud.TrimEnd('/');
        return string.Equals(aud, GraphAudienceUrl.TrimEnd('/'), StringComparison.OrdinalIgnoreCase) ||
               string.Equals(aud, GraphAudienceGuid, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsTrustedEntraIssuer(string iss)
    {
        if (!Uri.TryCreate(iss.Trim(), UriKind.Absolute, out var u) ||
            !string.Equals(u.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return TrustedIssuerHosts.Contains(u.Host);
    }

    private static bool TryGetAudiences(JsonElement root, out List<string> audiences)
    {
        audiences = [];
        if (!root.TryGetProperty("aud", out var aud))
        {
            return false;
        }

        if (aud.ValueKind == JsonValueKind.String)
        {
            var s = aud.GetString();
            if (!string.IsNullOrEmpty(s))
            {
                audiences.Add(s);
            }

            return audiences.Count > 0;
        }

        if (aud.ValueKind == JsonValueKind.Array)
        {
            foreach (var x in aud.EnumerateArray())
            {
                if (x.ValueKind == JsonValueKind.String)
                {
                    var s = x.GetString();
                    if (!string.IsNullOrEmpty(s))
                    {
                        audiences.Add(s);
                    }
                }
            }

            return audiences.Count > 0;
        }

        return false;
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2:
                s += "==";
                break;
            case 3:
                s += "=";
                break;
        }

        return Convert.FromBase64String(s);
    }
}
