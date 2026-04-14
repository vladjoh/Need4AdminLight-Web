# Security notes — Need4Admin Light

This document summarizes the threat model, controls shipped in the app, and what operators should still verify.

## What the app does

- Users sign in with **Microsoft Entra ID** in the browser (**MSAL + PKCE**). Passwords and MFA are handled only by Microsoft.
- The app receives a **delegated Microsoft Graph access token** and stores it in the **ASP.NET Core authentication cookie** (with the signed-in user’s claims) so Razor pages can call Graph on behalf of that user. The token is **not written to application databases** by this codebase; treat the cookie like any session secret.
- Reports are generated from **live Graph API** responses in the user’s session.

## Controls implemented in code

| Area | Mitigation |
|------|------------|
| **Session cookie** | `HttpOnly`, `SameSite=Lax`, `Secure` in non-Development, explicit name and sliding expiration. |
| **HTTPS / proxy** | `UseForwardedHeaders` for `X-Forwarded-Proto` / `X-Forwarded-For` on Azure App Service; `UseHttpsRedirection` and **HSTS** in production. |
| **Response headers** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, restrictive `Permissions-Policy`. |
| **`POST /internal/auth/session`** | **Same-origin** check (`Origin` / `Referer`) in production; **rate limiting** (fixed window per client IP); **64 KB** body size limit; JWT shape checks before accepting a token; Graph `/me` validates the token. |
| **Antiforgery** | Not used on the JSON session endpoint (browser MSAL flow); same-origin + `SameSite` cookies reduce cross-site posting risk. |

## Residual risks and hardening ideas

- **Host compromise**: Anyone with access to the server memory or logs could abuse tokens; use a hardened host, TLS, and minimal logging of secrets.
- **Token in cookie**: Stolen cookie ⇒ attacker can act as the user until expiry/sign-out. Use short sessions, sign out on shared machines, and **Entra Conditional Access** (e.g. compliant device, MFA).
- **Content-Security-Policy (CSP)**: Not set globally because sign-in pages use inline scripts for MSAL. You can add a strict CSP at the reverse proxy for static routes, or refactor sign-in to nonces.
- **Dependency updates**: Keep .NET, NuGet packages, and `wwwroot/js/msal-browser.min.js` patched.
- **Admin consent**: The app requests powerful **read** Graph scopes; only grant to trusted deployments and trusted users.

## Reporting

If you find a vulnerability, please open a **private** security advisory on the repository or contact the maintainers through GitHub.
