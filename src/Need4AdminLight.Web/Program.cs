using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Need4AdminLight.Web;
using Need4AdminLight.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Azure App Service (Linux): PORT is set; ensure Kestrel binds when ASPNETCORE_URLS is absent.
var portEnv = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrWhiteSpace(portEnv) &&
    string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASPNETCORE_URLS")))
{
    builder.WebHost.UseUrls($"http://0.0.0.0:{portEnv}");
}

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddHsts(options =>
{
    options.Preload = false;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(180);
});

builder.Services.Configure<Need4AdminOptions>(
    builder.Configuration.GetSection(Need4AdminOptions.SectionName));

builder.Services.AddHttpClient<GraphAuditService>(client =>
{
    client.Timeout = TimeSpan.FromMinutes(10);
});

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.Name = "Need4AdminLight.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
            ? CookieSecurePolicy.SameAsRequest
            : CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.LoginPath = "/signin";
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
    });

builder.Services.AddAuthorization();
builder.Services.AddMemoryCache();
builder.Services.AddRazorPages();

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("SessionEstablish", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(1)
            }));
});

var app = builder.Build();

app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append(
        "Permissions-Policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()");
    await next();
});

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapPost("/internal/auth/session", async Task (HttpContext http) =>
    {
        const long maxBodyBytes = 64 * 1024;
        if (http.Request.Headers.ContentLength is long cl && cl > maxBodyBytes)
        {
            http.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            await http.Response.WriteAsync("Request body too large.");
            return;
        }

        if (!app.Environment.IsDevelopment())
        {
            if (!SessionEstablishGuard.IsSameOrigin(http.Request))
            {
                http.Response.StatusCode = StatusCodes.Status403Forbidden;
                await http.Response.WriteAsync("Forbidden.");
                return;
            }
        }

        SessionEstablishRequest? body;
        try
        {
            body = await JsonSerializer.DeserializeAsync<SessionEstablishRequest>(
                http.Request.Body,
                (JsonSerializerOptions?)null,
                http.RequestAborted).ConfigureAwait(false);
        }
        catch
        {
            http.Response.StatusCode = StatusCodes.Status400BadRequest;
            await http.Response.WriteAsync("Invalid JSON body.");
            return;
        }

        if (body is null || string.IsNullOrWhiteSpace(body.AccessToken))
        {
            http.Response.StatusCode = StatusCodes.Status400BadRequest;
            await http.Response.WriteAsync("Missing accessToken.");
            return;
        }

        try
        {
            GraphAccessTokenGuard.ValidateOrThrow(body.AccessToken);
        }
        catch (Exception ex)
        {
            http.Response.StatusCode = StatusCodes.Status401Unauthorized;
            if (app.Environment.IsDevelopment())
            {
                await http.Response.WriteAsync(ex.Message);
            }
            else
            {
                await http.Response.WriteAsync("Invalid access token.");
            }

            return;
        }

        using var hc = new HttpClient();
        var profileRequest = new HttpRequestMessage(
            HttpMethod.Get,
            "https://graph.microsoft.com/v1.0/me?$select=displayName,userPrincipalName");
        profileRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", body.AccessToken);
        using var profileResponse = await hc.SendAsync(profileRequest, http.RequestAborted).ConfigureAwait(false);
        if (!profileResponse.IsSuccessStatusCode)
        {
            http.Response.StatusCode = StatusCodes.Status502BadGateway;
            await http.Response.WriteAsync("Could not read your profile from Microsoft Graph.");
            return;
        }

        await using var profileStream = await profileResponse.Content.ReadAsStreamAsync(http.RequestAborted).ConfigureAwait(false);
        using var profileDoc = await JsonDocument.ParseAsync(profileStream, cancellationToken: http.RequestAborted)
            .ConfigureAwait(false);

        var upn = profileDoc.RootElement.TryGetProperty("userPrincipalName", out var upnElement)
            ? upnElement.GetString() ?? string.Empty
            : string.Empty;
        var displayName = profileDoc.RootElement.TryGetProperty("displayName", out var dnElement)
            ? dnElement.GetString() ?? upn
            : upn;

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, upn),
            new("display_name", displayName)
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);
        var authProperties = new AuthenticationProperties();
        authProperties.StoreTokens(
        [
            new AuthenticationToken { Name = "access_token", Value = body.AccessToken },
            new AuthenticationToken { Name = "refresh_token", Value = string.Empty }
        ]);

        await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, authProperties)
            .ConfigureAwait(false);

        http.Response.ContentType = "application/json; charset=utf-8";
        await http.Response.WriteAsync("{\"ok\":true,\"redirect\":\"/Overview\"}").ConfigureAwait(false);
    })
    .AllowAnonymous()
    .DisableAntiforgery()
    .RequireRateLimiting("SessionEstablish");

app.MapGet("/signout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
    var azure = context.RequestServices.GetRequiredService<IConfiguration>().GetSection("AzureAd");
    var tenant = AuthConstants.TenantSegment(azure);
    var home = $"{context.Request.Scheme}://{context.Request.Host}/?signedout=1";
    var logout =
        $"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout?post_logout_redirect_uri={Uri.EscapeDataString(home)}";
    context.Response.Redirect(logout);
});

app.MapStaticAssets();
app.MapRazorPages().WithStaticAssets();

app.Run();
