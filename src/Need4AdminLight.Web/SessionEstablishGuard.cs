using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace Need4AdminLight.Web;

/// <summary>Reduces CSRF risk on <c>POST /internal/auth/session</c> by requiring browser same-origin headers.</summary>
public static class SessionEstablishGuard
{
    public static bool IsSameOrigin(HttpRequest request)
    {
        var expected = $"{request.Scheme}://{request.Host.Value}";
        if (request.Headers.TryGetValue(HeaderNames.Origin, out var origin) && !StringValues.IsNullOrEmpty(origin))
        {
            return string.Equals(origin.ToString(), expected, StringComparison.OrdinalIgnoreCase);
        }

        if (request.Headers.TryGetValue(HeaderNames.Referer, out var referer) && !StringValues.IsNullOrEmpty(referer) &&
            Uri.TryCreate(referer.ToString(), UriKind.Absolute, out var u))
        {
            return string.Equals($"{u.Scheme}://{u.Authority}", expected, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }
}
