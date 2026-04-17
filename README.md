# Need4Admin Light (web)

Lightweight, read-only web app for Microsoft Entra ID (Azure AD). Sign in with a work account, then generate in-browser reports: **privileged users** (Entra directory roles, Cloud/Hybrid, status) and **enterprise applications** (delegated and application API permissions, status, sensitive permission highlighting).

This repository is the webbased version build on **ASP.NET Core** of [Need4Admin](https://github.com/vladjoh/Need4Admin) PowerShell script. 

---

## Features

### Privileged users

- UPN, **status** (enabled/disabled), **account type** (Cloud / Hybrid)
- Active Entra directory roles; high-privileged roles highlighted
- Search, sortable columns, print-friendly layout

  ![git1](https://github.com/user-attachments/assets/14d90e4f-bac2-41cd-a2d6-58e05add5239)


### Applications

- Application name, enterprise object ID, app (client) ID
- **Status** (enabled/disabled) for the enterprise app (service principal)
- Delegated permissions and application (app-only) permissions
- High-impact API permissions highlighted for review

  ![git2](https://github.com/user-attachments/assets/2f38ed66-7492-4e8c-bc92-7b5668e8e0a4)


### Privacy / scope

- Read-only Graph calls; reports run in the user’s session
- Host **your own** instance if you do not want a third party running the app

---

## How it works

- **Runtime:** .NET 9 (ASP.NET Core, Razor Pages)
- **Auth:** **[MSAL.js](https://github.com/AzureAD/microsoft-authentication-library-for-js)** in the browser 
- **Data:** Microsoft Graph (delegated token from signed-in user)

---

## Prerequisites to host this tool in your environment 

- Host with [.NET 9 SDK](https://dotnet.microsoft.com/download) for local dev/prod. 
- Entra ID rights to register an application and grant admin consent for Graph permissions
- Operators running reports typically need Global Reader (or equivalent read access in your tenant)

See quick start guide: **[`TUTORIAL.md`](TUTORIAL.md)**.

---


## Contributing

Issues and pull requests are welcome. 
