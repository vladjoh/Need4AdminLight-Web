# Need4Admin Light (standalone web app) — Entra permissions

Deploy **`Need4AdminLight.Web`** as its own site. Use a **dedicated** Entra app registration. Sign-in requests the delegated scopes compiled into `Program.cs` (this SKU has no “full mode” toggle).

Configure display branding under **`Need4AdminLight:ProductName`** in `appsettings.json` if you want a custom title.

---

## Azure App Service — deploy

### Linux (most common for App Service)

`web.config` and **`Need4AdminLight.Web.exe`** are for **Windows/IIS only**. On **Linux**, deploy a **`linux-x64`** publish and set a **startup command**.

From repo root:

`powershell -ExecutionPolicy Bypass -File need4adminlight\Publish-Azure-Linux.ps1`

That creates **`Need4AdminLight-Publish-Linux`** and **`Need4AdminLight-Azure-Linux.zip`** (flat zip root: `Need4AdminLight.Web.dll`, nested **`wwwroot`**, etc.). The script tries **self-contained `linux-x64`** first; if restore fails, it falls back to **portable** publish (smaller output) which requires the **.NET 9** runtime on the Web App.

In Azure Portal → your Web App → **Configuration** → **General settings**:

- **Startup Command:** `dotnet Need4AdminLight.Web.dll`
- **Stack:** **.NET 9 (Linux)** — required unless self-contained publish succeeded (then runtime is bundled; stack should still be a .NET app, often **.NET 9**).

ZIP Deploy **`Need4AdminLight-Azure-Linux.zip`**, then **Restart**. Zip root must be files directly (no extra parent folder).

Do **not** rely on **`Need4AdminLight.Web.exe`** or **`web.config`** on Linux; they are harmless if present but IIS is not used.

### Windows (IIS)

`powershell -ExecutionPolicy Bypass -File need4adminlight\Publish-Azure-Windows.ps1`

Produces **`Need4AdminLight-Publish`** and **`Need4AdminLight-Azure.zip`** with **`web.config`**. ZIP Deploy and restart.

---

## Microsoft Graph — Delegated (admin consent)

These are the **only** API permissions the web app requests (see `Program.cs` and the home page).

| Permission | Purpose |
|------------|---------|
| `openid` | OpenID Connect sign-in |
| `User.Read` | Signed-in operator |
| `User.Read.All` | User profiles in the privileged-users report |
| `Directory.Read.All` | Directory roles and members, group transitive members, `oauth2PermissionGrants` |
| `RoleManagement.Read.Directory` | Unified and transitive directory role assignments |
| `RoleAssignmentSchedule.Read.Directory` | Active PIM schedules and instances |
| `Application.Read.All` | Service principals and app role assignments for the applications report |

This SKU does **not** read authentication methods or audit/report sign-in APIs (`UserAuthenticationMethod.Read.All`, `AuditLog.Read.All` are omitted). `Group.Read.All` is omitted; group membership for role expansion uses paths covered by `Directory.Read.All`.

**Required role to read report:** Global Reader (or equivalent) is typical for delegated directory reads.

**Consent:** After editing **App registrations → API permissions**, use **Grant admin consent** on the **enterprise application** in each tenant, then have users **sign out and sign in**.

---

## UI (this build)

- **Applications:** Display name, enterprise object ID, app (client) ID, delegated scopes and application (app role) permissions.
- **Privileged users:** UPN, account status (Active/Disabled), account type (Cloud/Hybrid), active Entra directory roles (high‑privileged Entra roles highlighted), free-text search, total users in report. Azure RBAC is not in this web SKU — use the PowerShell report on GitHub.

For deeper eligibility, audit logs, and the full PowerShell report, use [Need4Admin on GitHub](https://github.com/vladjoh/Need4Admin).
