using System.Text.Json.Serialization;

namespace Need4AdminLight.Web;

/// <summary>POST /internal/auth/session body. Property name matches browser <c>JSON.stringify({ accessToken })</c>.</summary>
public sealed record SessionEstablishRequest(
    [property: JsonPropertyName("accessToken")] string? AccessToken);
