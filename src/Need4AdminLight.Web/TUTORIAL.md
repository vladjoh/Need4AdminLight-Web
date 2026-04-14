# Need4Admin Light — setup tutorial (new environment)

Sign-in matches the **Intune Assignments** style: **[MSAL.js](https://github.com/AzureAD/microsoft-authentication-library-for-js)** runs in the browser and completes the **authorization code flow with PKCE**. **No client secret** is used. The server only receives the Graph **access token** over HTTPS and opens a **cookie session** (same as before for reports).

---

## 1. Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download) (for local dev / publish)
- Entra ID rights to **register an application** and **grant admin consent** for Graph permissions
- Operators running reports typically need **Global Reader** (or equivalent read access in your tenant)

---

## 2. Register an app in Microsoft Entra ID

1. Open **[Microsoft Entra admin center](https://entra.microsoft.com/)** → **Identity** → **Applications** → **App registrations** → **New registration**.
2. **Name:** e.g. `Need4Admin Light`.
3. **Supported account types:**  
   - *Accounts in this organizational directory only* (single tenant), or  
   - *Multitenant* if you need guests / multiple orgs (match your security model).
4. **Redirect URI** (important — use **SPA**, not Web):  
   - Click **Single-page application**  
   - Local dev: `http://localhost:5000/signin-callback`  
   - Production: `https://your-domain/signin-callback`  
   The path must match `AzureAd:CallbackPath` in `appsettings.json` (default `/signin-callback`). The full URL must match what the app builds (`https://host` + callback path).
5. Click **Register**.

Copy the **Application (client) ID**.  
Use **Directory (tenant) ID** in `AzureAd:TenantId` only for single-tenant; otherwise use `organizations`.

**You do not need** “Allow public client flows” for this model (MSAL browser + SPA redirect). You do **not** create a client secret.

---

## 3. API permissions (Microsoft Graph — Delegated)

**API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions**. Add:

| Permission | Purpose |
|------------|---------|
| `openid` | Sign-in |
| `User.Read` | Signed-in user |
| `User.Read.All` | User profiles in privileged-users report |
| `Directory.Read.All` | Directory roles, groups, OAuth2 grants |
| `RoleManagement.Read.Directory` | Role assignments |
| `RoleAssignmentSchedule.Read.Directory` | PIM active assignments |
| `Application.Read.All` | Enterprise apps / app roles |

Click **Grant admin consent for [tenant]**.

---

## 4. Configure the web app

Edit `appsettings.json` (or use environment variables / App Service **Configuration**):

| Key | Example | Notes |
|-----|---------|--------|
| `AzureAd:ClientId` | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | Application (client) ID |
| `AzureAd:TenantId` | `organizations` | Work/school accounts from many tenants; or your **tenant GUID** for single-tenant |
| `AzureAd:CallbackPath` | `/signin-callback` | Must match the path in your Entra **SPA** redirect URI |

**Environment variables** (Azure App Service):

- `AzureAd__ClientId`
- `AzureAd__TenantId`

**No `ClientSecret`.**

---

## 5. Run locally

```bash
cd path/to/Need4AdminLight.Web
dotnet run
```

Open the URL shown (e.g. `http://localhost:5000`). Use **Sign in** → Microsoft login → you land on `/signin-callback` briefly → **Overview**.

### Troubleshooting

- **“No sign-in result”** — start from `/signin` again; clear site data / sessionStorage if stuck.
- **401 / Invalid access token** — SPA redirect URI must **exactly** match `http://localhost:PORT/signin-callback` (including port).
- **CSP / script blocked** — the page loads MSAL from `alcdn.msauth.net`. Allow that host in **Content-Security-Policy** if you add a strict CSP.
- **502 from Graph** — consent or missing delegated permissions.

---

## 6. Deploy to Azure App Service (example)

1. Create a **Web App**, **.NET 9** stack.
2. Deploy your **publish** output.
3. Set `AzureAd__ClientId`, `AzureAd__TenantId`.
4. In Entra, add **SPA** redirect: `https://<your-app>.azurewebsites.net/signin-callback` (exact URL).

---

## 7. Security notes

- MSAL runs in the **browser**; the **access token** is sent once to **`POST /internal/auth/session`** over HTTPS to create an **HttpOnly** cookie session for Razor pages.
- JWT **signature** is enforced when **Microsoft Graph** accepts the token; the app also checks **exp**, **aud** (Graph), and **iss** on the payload before calling Graph.
- **AGPL-3.0:** If you modify the app and host it as a network service for others, comply with source-offer requirements (see `LICENSE`).

---

## 8. Related docs in repo

- `PERMISSIONS.md` — permission rationale  
- `ENTRA-APP-PERMISSIONS.md` — Entra consent surface  

For the full PowerShell-oriented tool, see [Need4Admin on GitHub](https://github.com/vladjoh/Need4Admin).
