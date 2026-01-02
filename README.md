# Sophos Web Control – Local Sites GUI (local host)

A **Flask** application that serves a local GUI to manage **Local Sites** in Sophos Central Web Control.
The server acts as a **backend proxy** to Sophos APIs, so the browser talks **only to `localhost`** and you
avoid **CORS** issues entirely.

> **Security**: client credentials and tokens are kept **only in process memory (RAM)**, **never on disk**.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Run](#run)
- [Using the GUI](#using-the-gui)
- [Local APIs](#local-apis)
- [Security & Privacy](#security--privacy)
- [Troubleshooting](#troubleshooting)
- [Optional packaging (PyInstaller)](#optional-packaging-pyinstaller)
- [Operational notes](#operational-notes)

---

## Features

- **Modern UI** as a single-file HTML/CSS/JS served by Flask (`GET /`).
- **Backend login** with `client_credentials`: retrieves a JWT from Sophos IDP.
- **WhoAmI** call to determine `tenantId`, `dataRegion`, and `api_base` automatically.
- **List**, **add**, and **delete** Local Sites via **local endpoints** that proxy Sophos APIs.
- **CORS solved**: the browser calls `http://localhost:5000/api/...` only.
- State (credentials, token, tenant/region) is in **RAM only**; a restart **resets** everything.
- **Pagination** support to fetch the complete list.

---

## Architecture

```
Browser (GUI) ────► Flask (localhost:5000) ────► Sophos APIs
   │                       │
   │  /api/login           └─ HEADERS: Authorization Bearer + X-Tenant-ID
   │  /api/local-sites
   └  /api/local-sites/:id
```

**Main files**
- `app.py`: Flask server + embedded UI (string `INDEX_HTML`).

---

## Prerequisites

- **Python 3.9+** (3.11 on Windows 11 recommended).
- Python packages:
  - `flask`
  - `requests`

> A virtual environment is not strictly required, but recommended for isolation.

---

## Installation

```powershell
# Windows (PowerShell)
py -m pip install flask requests
```

(or `python -m pip install flask requests`)

---

## Run

```powershell
py app.py
# then open your browser at
http://localhost:5000
```

If Windows Firewall prompts, **allow local access**.

---

## Using the GUI

1. **Login**: enter **Client ID** and **Client Secret** (registered Sophos app).
2. The GUI calls `POST /api/login`. The server:
   - obtains a token from `oauth2/token`,
   - calls **WhoAmI** (`/whoami/v1`) and populates state (`tenantId`, `dataRegion`, `api_base`).
3. **Refresh list**: `GET /api/local-sites?all=true` to fetch all pages.
4. **Add Local Site**: enter `URL` and **Tags** _or_ `categoryId` + optional `comment`.
5. **Delete**: click **Delete** next to an item (DELETE).

---

## Local APIs

> All APIs run **on `localhost:5000`** and proxy to Sophos.

### `POST /api/login`
Request:
```json
{
  "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "client_secret": "***************"
}
```
Response (200/401/400):
```json
{
  "ok": true,
  "tenantId": "abcdef01-....",
  "dataRegion": "eu01",
  "apiBase": "https://api-eu01.central.sophos.com"
}
```

### `GET /api/local-sites`
Query params:
- `all` (default `true`): when `true`, fetch **all** pages.
- `page` (default `1`): specific page when `all=false`.
- `pageTotal` (default `true`): include pagination metadata.

Response:
```json
{
  "ok": true,
  "items": [
    {
      "id": "123",
      "url": "https://example.com",
      "tags": ["allow", "marketing"],
      "comment": "note",
      "categoryId": 50
    }
  ],
  "pages": { "total": 3 }
}
```

### `POST /api/local-sites`
Body:
```json
{
  "url": "https://www.example.com",
  "tags": ["allow","vip"],       
  "categoryId": 50,                
  "comment": "reason / ticket"
}
```
Response (201):
```json
{
  "ok": true,
  "item": { "id": "...", "url": "...", "tags": ["..."], "comment": "...", "categoryId": 50 }
}
```

### `DELETE /api/local-sites/{id}`
Response:
```json
{ "ok": true }
```

---

## Security & Privacy

- **No disk storage**: `client_id`, `client_secret`, token, and tenant/region remain **in RAM**.
- **Minimal logging**: `_log()` avoids printing secrets.
- **Token renewal**: automatic, 60 seconds before expiration.
- **CORS**: headers added in `@after_request`; the expected origin is `http://localhost:*`.

> If you distribute beyond a local PC, consider:
> - rate limiting,
> - extra server-side authentication,
> - port segregation / firewalling,
> - code signing (see Packaging).

---

## Troubleshooting

- **401 / Authentication failed**  
  Check `client_id`/`client_secret` and that the Sophos app has the `token` scope enabled.

- **WhoAmI failed / `Data region not set`**  
  `whoami` must return `apiHosts.dataRegion` or `dataRegion`. If the payload shape differs, verify the app permissions and environment (tenant vs partner).

- **Empty list / 500 on `/api/local-sites`**  
  Inspect the upstream response: network, timeouts, or permission issues. Try refreshing the list from the GUI.

- **Port in use (5000)**  
  Change the port in `app.run(host="127.0.0.1", port=5000, ...)`.

- **Firewall / SmartScreen**  
  Allow local access. If you ship an unsigned `.exe`, SmartScreen may show warnings.

---

## Optional packaging (PyInstaller)

Create a portable Windows executable:

```powershell
py -m pip install pyinstaller
py -m PyInstaller --onefile --name SophosLocalSites app.py
# The executable will be in .\dist\SophosLocalSites.exe
```

> **Code signing (optional)**: if you distribute the executable to other users,
> sign it with `signtool` using a **code signing certificate** and a **timestamp server**.

Example (short):
```powershell
signtool sign /f "C:\path\to\cert.pfx" /p "PASSWORD" `
  /fd sha256 /td sha256 /tr http://timestamp.digicert.com `
  ".\dist\SophosLocalSites.exe"

signtool verify /pa /v ".\dist\SophosLocalSites.exe"
```

---

## Operational notes

- **Local-only usage**: design focused on reducing risk and complexity (CORS and storage).
- **UI cache**: the table keeps the fetched data until you press **Refresh list**.
- **Tags vs Category ID**: backend sends either `tags` **or** `categoryId`; `comment` is optional.

