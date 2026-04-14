# Need4Admin Light (web)

Lightweight, read-only web app for Microsoft Entra ID (Azure AD). Sign in with a work account, then generate in-browser reports: **privileged users** (Entra directory roles, Cloud/Hybrid, status) and **enterprise applications** (delegated and application API permissions, status, sensitive permission highlighting).

This repository is the **ASP.NET Core** companion to the fuller [Need4Admin](https://github.com/vladjoh/Need4Admin) PowerShell tooling. It uses a **minimal delegated Graph permission set** and does not persist tenant directory data on the server beyond normal session/cookie handling you configure.

---

## Features

### Privileged users

- UPN, **status** (enabled/disabled), **account type** (Cloud / Hybrid)
- Active Entra directory roles; high-privileged roles highlighted
- Search, sortable columns, print-friendly layout

### Applications

- Application name, enterprise object ID, app (client) ID
- **Status** (enabled/disabled) for the enterprise app (service principal)
- Delegated permissions and application (app-only) permissions
- High-impact API permissions highlighted for review

### Privacy / scope

- Read-only Graph calls; reports run in the user’s session
- Host **your own** instance if you do not want a third party running the app

---

## How it works

- **Runtime:** .NET 9 (ASP.NET Core, Razor Pages)
- **Auth:** **[MSAL.js](https://github.com/AzureAD/microsoft-authentication-library-for-js)** in the browser 
- **Data:** Microsoft Graph (delegated token from signed-in user)

---

## Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download)
- Entra ID permission to **register an application** (or use an existing app registration)
- **Global Reader** (or equivalent) recommended for operators running reports

---

## Quick start

Full step-by-step (Entra screens, troubleshooting): **[`TUTORIAL.md`](TUTORIAL.md)**.

### 1. Clone

```bash
git clone https://github.com/YOUR_ORG/Need4AdminLight-Website.git
cd Need4AdminLight-Website
```

### 2. Entra app registration (summary)

1. **App registrations** → **New registration** → add a **Single-page application** redirect URI, e.g. `http://localhost:5000/signin-callback` (must match `AzureAd:CallbackPath`). **Do not** use the “Web” platform for this URI — MSAL in the browser requires **SPA** redirects.
2. **API permissions** → Microsoft Graph **Delegated**: `openid`, `User.Read`, `User.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `RoleAssignmentSchedule.Read.Directory`, `Application.Read.All` → **Grant admin consent**.


### 3. Configuration

Edit `src/Need4AdminLight.Web/appsettings.json` (or use environment variables):

- `AzureAd:ClientId` — Application (client) ID  
- `AzureAd:TenantId` — `organizations` (work/school accounts) or your **tenant GUID** for single-tenant


On host side, use application settings such as `AzureAd__ClientId` and `AzureAd__TenantId`.

### 4. Run locally

```bash
cd src/Need4AdminLight.Web
dotnet run
```

Open the URL shown (e.g. `http://localhost:5000`). Sign in → **Overview** → generate a report.

---

## Publish 

Framework-dependent deployment (runtime installed on the host):

```bash
cd src/Need4AdminLight.Web
dotnet publish -c Release -o ./publish -p:UseAppHost=false --self-contained false
```

Deploy the `publish` folder contents. Set `PORT` / `ASPNETCORE_URLS` as required; the app binds to `PORT` on Azure Linux when configured.


## License

Licensed under the **GNU Affero General Public License v3.0** — see [`LICENSE`](LICENSE).

**AGPL note for network use:** If you **modify** this software and **run it as a network service** for others, the license requires you to offer those users a way to obtain the **Corresponding Source** of your version (see section 13 of the AGPL). Use an unmodified copy, link prominently to this repository, or comply as appropriate for your deployment.

Third-party assets under `wwwroot/lib/` remain under their original licenses.

Copyright and attribution: see [`NOTICE`](NOTICE). Update `NOTICE` with your legal name or org if you are the primary copyright holder.

---

## Contributing

Issues and pull requests are welcome. 
