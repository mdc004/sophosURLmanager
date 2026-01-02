
# app.py
# -*- coding: utf-8 -*-
#
# Sophos Web Control – Local Sites GUI hosted locally
# Serve la UI e fa da proxy alle API Sophos Central per evitare CORS.
# Sicurezza: credenziali e token sono mantenuti SOLO in memoria di processo.
# Avvio:  python app.py   poi apri http://localhost:5000

import json
import time
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urlencode

import requests
from flask import Flask, Response, jsonify, request, make_response

app = Flask(__name__)

# ---- Stato in memoria (RAM di processo) ----
STATE: Dict[str, Any] = {
    "client_id": None,
    "client_secret": None,
    "tenant_id": None,
    "data_region": None,   # es. "eu01", "us01", ...
    "api_base": None,      # es. "https://api-eu01.central.sophos.com"
    "access_token": None,
    "token_exp": 0,        # epoch seconds
}

# ---- Costanti API Sophos ----
SOPHOS_IDP_TOKEN_URL = "https://id.sophos.com/api/v2/oauth2/token"
WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"
LOCAL_SITES_PATH = "/endpoint/v1/settings/web-control/local-sites"

def _log(msg: str):
    # Logging minimalista (non stampa segreti)
    print(f"[sophos-local] {msg}")

# ---------------- Token & WhoAmI ----------------

def need_new_token() -> bool:
    # Rinnova 60 secondi prima della scadenza
    return (not STATE.get("access_token")) or time.time() > (STATE.get("token_exp", 0) - 60)

def obtain_token() -> Tuple[bool, str]:
    """Ottiene un JWT da Sophos IDP con client_credentials."""
    cid = STATE.get("client_id")
    csec = STATE.get("client_secret")
    if not cid or not csec:
        return False, "Client ID / Secret non impostati."

    data = {
        "grant_type": "client_credentials",
        "client_id": cid,
        "client_secret": csec,
        "scope": "token",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        resp = requests.post(SOPHOS_IDP_TOKEN_URL, headers=headers, data=urlencode(data), timeout=20)
        if resp.status_code != 200:
            return False, f"Token error: {resp.status_code} {resp.text}"
        js = resp.json()
        STATE["access_token"] = js.get("access_token")
        expires_in = js.get("expires_in", 3600)
        STATE["token_exp"] = int(time.time()) + int(expires_in)
        return True, "ok"
    except Exception as e:
        return False, f"Eccezione token: {e}"

def _extract_region_and_base(whoami_json: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Prova ad estrarre tenantId e dataRegion e calcola api_base.
    Preferisce host espliciti in whoami.apiHosts se presenti.
    """
    tid = whoami_json.get("id") or whoami_json.get("tenantId")

    # Possibili forme di whoami:
    # - {"dataRegion": "eu01", "apiHosts": {"dataRegion": "https://api-eu01.central.sophos.com", ...}}
    # - {"apiHosts": {"global": "https://api.central.sophos.com", "dataRegion": "https://api-eu01.central.sophos.com"}}
    # - {"dataRegion": "eu01"} senza apiHosts (meno frequente)

    api_base = None
    dr = None

    api_hosts = whoami_json.get("apiHosts") or {}
    # Se c'è un host specifico per dataRegion, usalo
    host_dr = api_hosts.get("dataRegion")
    if isinstance(host_dr, str) and "central.sophos.com" in host_dr:
        api_base = host_dr
        try:
            # estrae eu01 da "https://api-eu01.central.sophos.com"
            dr = host_dr.split("api-")[1].split(".")[0]
        except Exception:
            pass

    # Se non abbiamo dr, prova campo dataRegion diretto
    if not dr:
        dr = whoami_json.get("dataRegion")

    # Se ancora manca api_base ma abbiamo dr, costruiscilo
    if not api_base and dr:
        api_base = f"https://api-{dr}.central.sophos.com"

    return tid, dr, api_base

def call_whoami() -> Tuple[bool, str]:
    """Chiama Who-am-I per ricavare tenant, data region e api_base."""
    ok, msg = ensure_token()
    if not ok:
        return ok, msg

    headers = {"Authorization": f"Bearer {STATE['access_token']}"}
    try:
        resp = requests.get(WHOAMI_URL, headers=headers, timeout=20)
        if resp.status_code != 200:
            return False, f"Whoami error: {resp.status_code} {resp.text}"
        js = resp.json()
        tid, dr, base = _extract_region_and_base(js)
        if not tid or not dr or not base:
            return False, "Whoami: impossibile determinare tenant/dataRegion/api_base"
        STATE["tenant_id"] = tid
        STATE["data_region"] = dr
        STATE["api_base"] = base
        _log(f"Whoami OK: tenant={tid}, dataRegion={dr}, api_base={base}")
        return True, "ok"
    except Exception as e:
        return False, f"Eccezione whoami: {e}"

def ensure_token() -> Tuple[bool, str]:
    """Assicura che access_token sia valido; altrimenti rinnova."""
    if need_new_token():
        return obtain_token()
    return True, "ok"

def sophos_headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Header per chiamate Endpoint API."""
    h = {
        "Authorization": f"Bearer {STATE['access_token']}",
        "X-Tenant-ID": STATE["tenant_id"],
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if extra:
        h.update(extra)
    return h

# ---------------- Endpoint helpers ----------------

def list_local_sites(all_pages: bool = True, page: int = 1, page_total: bool = True) -> Tuple[bool, Any]:
    """GET /endpoint/v1/settings/web-control/local-sites, supporta paginazione."""
    ok, msg = ensure_token()
    if not ok:
        return False, msg
    base = STATE.get("api_base")
    if not base:
        return False, "Data region / api_base non impostata."

    url = f"{base}{LOCAL_SITES_PATH}"
    try:
        if not all_pages:
            params = []
            if page_total:
                params.append("pageTotal=true")
            if page and page > 0:
                params.append(f"page={page}")
            if params:
                url = f"{url}?{'&'.join(params)}"
            resp = requests.get(url, headers=sophos_headers(), timeout=30)
            if resp.status_code != 200:
                return False, f"List error: {resp.status_code} {resp.text}"
            return True, resp.json()

        # Recupera tutte le pagine
        items: List[Dict[str, Any]] = []
        cur = 1
        total_pages = 1
        while True:
            u = f"{url}?pageTotal=true&page={cur}"
            resp = requests.get(u, headers=sophos_headers(), timeout=30)
            if resp.status_code != 200:
                return False, f"List error: {resp.status_code} {resp.text}"
            js = resp.json()
            page_items = js.get("items") or js.get("data") or []
            items.extend(page_items)
            pages_info = js.get("pages") or {}
            total_pages = int(pages_info.get("total", cur))
            if cur >= total_pages:
                break
            cur += 1
        return True, {"items": items, "pages": {"total": total_pages}}
    except Exception as e:
        return False, f"Eccezione list: {e}"

def add_local_site(url_value: str, tags: Optional[list] = None, comment: Optional[str] = None,
                   category_id: Optional[int] = None) -> Tuple[bool, Any]:
    """POST /endpoint/v1/settings/web-control/local-sites"""
    ok, msg = ensure_token()
    if not ok:
        return False, msg
    base = STATE.get("api_base")
    if not base:
        return False, "Data region / api_base non impostata."

    payload = {"url": url_value}
    if tags:
        payload["tags"] = tags
    if comment:
        payload["comment"] = comment
    if category_id is not None:
        payload["categoryId"] = category_id

    try:
        resp = requests.post(f"{base}{LOCAL_SITES_PATH}", headers=sophos_headers(), data=json.dumps(payload), timeout=30)
        if resp.status_code not in (200, 201):
            return False, f"Add error: {resp.status_code} {resp.text}"
        return True, resp.json()
    except Exception as e:
        return False, f"Eccezione add: {e}"

def delete_local_site(item_id: str) -> Tuple[bool, str]:
    """DELETE /endpoint/v1/settings/web-control/local-sites/{id}"""
    ok, msg = ensure_token()
    if not ok:
        return False, msg
    base = STATE.get("api_base")
    if not base:
        return False, "Data region / api_base non impostata."
    try:
        resp = requests.delete(f"{base}{LOCAL_SITES_PATH}/{item_id}", headers=sophos_headers(), timeout=30)
        if resp.status_code not in (200, 204):
            return False, f"Delete error: {resp.status_code} {resp.text}"
        return True, "ok"
    except Exception as e:
        return False, f"Eccezione delete: {e}"

# ---------------- CORS (per eventuali accessi cross-port) ----------------

@app.after_request
def add_cors_headers(response):
    # Non strettamente necessario se UI e API sono stesso origin (localhost:5000),
    # ma utile se apri la pagina su altra porta.
    origin = request.headers.get("Origin")
    if origin and origin.startswith("http://localhost"):
        response.headers["Access-Control-Allow-Origin"] = origin
    else:
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:5000"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Tenant-ID"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return response

@app.route("/api/<path:_>", methods=["OPTIONS"])
def cors_preflight(_):
    return make_response(("", 204))

# ---------------- API locali (proxate) ----------------

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True) or {}
    cid = (data or {}).get("client_id")
    csec = (data or {}).get("client_secret")
    if not cid or not csec:
        return jsonify({"ok": False, "error": "Client ID/Secret mancanti"}), 400

    # Reset stato e imposta nuove credenziali
    STATE.update({
        "client_id": cid.strip(),
        "client_secret": csec.strip(),
        "tenant_id": None,
        "data_region": None,
        "api_base": None,
        "access_token": None,
        "token_exp": 0,
    })

    ok, msg = obtain_token()
    if not ok:
        _log(msg)
        return jsonify({"ok": False, "error": "Autenticazione fallita"}), 401

    ok, msg = call_whoami()
    if not ok:
        _log(msg)
        return jsonify({"ok": False, "error": "Whoami fallito"}), 400

    return jsonify({
        "ok": True,
        "tenantId": STATE["tenant_id"],
        "dataRegion": STATE["data_region"],
        "apiBase": STATE["api_base"],
    })

@app.route("/api/local-sites", methods=["GET"])
def api_list_local_sites():
    # Recupera tutte le pagine di default
    all_param = request.args.get("all", "true").lower() != "false"
    page = int(request.args.get("page", "1"))
    page_total = request.args.get("pageTotal", "true").lower() == "true"

    ok, res = list_local_sites(all_pages=all_param, page=page, page_total=page_total)
    if not ok:
        _log(str(res))
        return jsonify({"ok": False, "error": res}), 500

    if isinstance(res, dict) and "items" in res:
        return jsonify({"ok": True, "items": res["items"], "pages": res.get("pages")})
    # Forma singola pagina
    items = res if isinstance(res, list) else res.get("items") or res.get("data") or []
    return jsonify({"ok": True, "items": items})

@app.route("/api/local-sites", methods=["POST"])
def api_add_local_site():
    data = request.get_json(force=True) or {}
    url_value = data.get("url")
    tags = data.get("tags") or []
    category_id = data.get("categoryId")
    comment = data.get("comment")
    if not url_value:
        return jsonify({"ok": False, "error": "URL mancante"}), 400

    ok, res = add_local_site(url_value=url_value, tags=tags, comment=comment, category_id=category_id)
    if not ok:
        return jsonify({"ok": False, "error": res}), 500
    return jsonify({"ok": True, "item": res}), 201

@app.route("/api/local-sites/<item_id>", methods=["DELETE"])
def api_delete_local_site(item_id: str):
    if not item_id:
        return jsonify({"ok": False, "error": "id mancante"}), 400
    ok, res = delete_local_site(item_id)
    if not ok:
        return jsonify({"ok": False, "error": res}), 500
    return jsonify({"ok": True})

# ---------------- Frontend (HTML statico, adattato a /api/*) ----------------

INDEX_HTML = r"""<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sophos Web Control – Local Sites GUI</title>
  <style>
    :root{--bg:#0f172a;--panel:#111827;--card:#1f2937;--muted:#94a3b8;--text:#e5e7eb;--accent:#22c55e;--accent-2:#60a5fa;--danger:#ef4444;--warn:#f59e0b;--border:#374151}
    *{box-sizing:border-box}
    body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:linear-gradient(135deg,#0b1022 0%,#0f172a 100%);color:var(--text)}
    header{padding:18px 20px;background:rgba(17,24,39,.7);backdrop-filter:blur(6px);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:5;display:flex;align-items:center;justify-content:space-between;gap:16px}
    header h1{margin:0;font-size:18px;font-weight:600;letter-spacing:.2px}
    header .status{font-size:12px;color:var(--muted)}
    main{padding:20px;max-width:95%;margin:0 auto}
    .grid{display:grid;gap:16px}
    @media (min-width:960px){.grid.cols-2{grid-template-columns:1.1fr 1fr}.grid.cols-3{grid-template-columns:repeat(3,1fr)}}
    .card{background:linear-gradient(180deg,rgba(31,41,55,.9),rgba(17,24,39,.9));border:1px solid var(--border);border-radius:12px;padding:16px;box-shadow:0 6px 24px rgba(0,0,0,.25)}
    .card h2{margin:0 0 10px 0;font-size:16px}
    .row{display:flex;gap:10px;align-items:center}
    .row.wrap{flex-wrap:wrap}
    label{font-size:12px;color:var(--muted);display:block;margin-bottom:4px}
    input[type="text"],input[type="password"],input[type="number"],textarea,select{width:100%;background:#0b1220;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:10px;outline:none}
    textarea{min-height:60px}
    .btn{background:#0b1220;color:var(--text);border:1px solid var(--border);padding:10px 12px;border-radius:10px;cursor:pointer}
    .btn.primary{border-color:transparent;background:linear-gradient(90deg,#22c55e,#16a34a);color:#052e16;font-weight:600}
    .btn.blue{border-color:transparent;background:linear-gradient(90deg,#60a5fa,#3b82f6);color:#011028;font-weight:600}
    .btn.warn{background:linear-gradient(90deg,#f59e0b,#d97706);border-color:transparent;color:#160f01;font-weight:600}
    .btn.danger{background:linear-gradient(90deg,#ef4444,#dc2626);border-color:transparent;color:#2d0606;font-weight:600}
    .btn:disabled{opacity:.6;cursor:not-allowed}
    .hint{font-size:12px;color:var(--muted)}
    .pill{padding:2px 8px;border:1px solid var(--border);border-radius:999px;font-size:12px;color:var(--muted)}
    .sep{height:1px;background:var(--border);margin:10px 0;opacity:.7}
    .hidden{display:none !important}
    table{width:100%;border-collapse:collapse;position:relative}
    thead th{text-align:left;font-weight:600;font-size:12px;color:var(--muted);border-bottom:1px solid var(--border);padding:8px;background:linear-gradient(180deg,rgba(31,41,55,.9),rgba(17,24,39,.9))}
    tbody td{border-bottom:1px dashed #2a3446;padding:10px 8px;vertical-align:top;font-size:14px;background:linear-gradient(180deg,rgba(31,41,55,.9),rgba(17,24,39,.9))}
    .tags{display:flex;gap:6px;flex-wrap:wrap}
    .flex{display:flex;gap:10px;align-items:center}
    .right{margin-left:auto}
    .toast{position:fixed;right:16px;bottom:16px;background:#001427;color:#d1fae5;border:1px solid #134e4a;padding:12px 14px;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.35)}
    .danger-toast{background:#2a0b0b;color:#fee2e2;border-color:#7f1d1d}
    .muted{color:var(--muted)}
    .mono{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace}
    .filters-pills{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
    .comment-cell{overflow-wrap:anywhere;word-break:break-word}
    th.sticky-right,td.sticky-right{position:sticky;right:0;background:linear-gradient(180deg,rgba(31,41,55,.95),rgba(17,24,39,.95));backdrop-filter:blur(2px);z-index:2}
    th.sticky-right{z-index:3}
    .actions-cell{min-width:140px;text-align:right}
  </style>
</head>
<body>
<header>
  <h1>Website Management – Local Sites (Sophos)</h1>
  <div class="status" id="statusLine">Non autenticato</div>
</header>

<main>
  <div class="grid cols-2">
    <section class="card" id="loginCard">
      <h2>Accesso API</h2>
      <div class="grid">
        <div>
          <label for="clientId">Client ID</label>
          <input id="clientId" type="text" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" autocomplete="off" />
        </div>
        <div>
          <label for="clientSecret">Client Secret</label>
          <input id="clientSecret" type="password" placeholder="••••••••••••••••••••" autocomplete="off" />
        </div>
      </div>
      <div class="row" style="margin-top:10px">
        <button class="btn primary" id="btnLogin">Accedi</button>
        <span class="hint">Le credenziali restano solo in memoria (nessun cookie/storage).</span>
      </div>
      <input id="inMemoryCreds" type="hidden" value="" />
    </section>

    <section class="card" id="actionsCard" aria-disabled="true">
      <h2>Azioni</h2>
      <div class="row wrap">
        <button class="btn blue" id="btnFetch" disabled>🔄 Aggiorna lista</button>
        <button class="btn" id="btnDownload" disabled>⬇️ Scarica cache (.json)</button>
        <button class="btn warn" id="btnLogout" disabled>⎋ Logout</button>
        <span class="hint">La lista è in cache finché non premi “Aggiorna lista”.</span>
      </div>
      <div class="sep"></div>
      <div class="grid cols-3">
        <div>
          <label for="searchUrl">Ricerca per URL</label>
          <div class="row">
            <input id="searchUrl" type="text" placeholder="es. *.example.com" />
            <button class="btn" id="btnSearchUrl">Cerca</button>
          </div>
        </div>
        <div>
          <label for="searchTagCat">Ricerca per Category/Tags</label>
          <div class="row">
            <input id="searchTagCat" type="text" placeholder="es. tag:marketing o categoryId:50" />
            <button class="btn" id="btnSearchTagCat">Cerca</button>
          </div>
          <div class="hint">Match su <em>categoryId</em> o su qualunque tag.</div>
        </div>
        <div>
          <label for="searchComment">Ricerca per Comment</label>
          <div class="row">
            <input id="searchComment" type="text" placeholder="es. 'temporaneo'" />
            <button class="btn" id="btnSearchComment">Cerca</button>
          </div>
        </div>
      </div>
      <div class="row" style="margin-top:8px">
        <button class="btn" id="btnClear">Pulisci filtri</button>
        <div class="filters-pills">
          <span class="pill" id="pillUrl" style="display:none"></span>
          <span class="pill" id="pillTagCat" style="display:none"></span>
          <span class="pill" id="pillComment" style="display:none"></span>
        </div>
      </div>
    </section>
  </div>

  <section class="card" id="addCard" aria-disabled="true" style="margin-top:16px">
    <h2>Aggiungi Local Site</h2>
    <div class="grid cols-3">
      <div>
        <label for="newUrl">URL <span class="pill">obbligatorio</span></label>
        <input id="newUrl" type="text" placeholder="https://www.example.com" />
      </div>
      <div>
        <label>Modalità</label>
        <div class="row">
          <label class="row"><input type="radio" name="mode" value="tags" checked />&nbsp;Tags</label>
          <label class="row"><input type="radio" name="mode" value="category" />&nbsp;Category ID</label>
        </div>
      </div>
      <div id="tagsBox">
        <label for="newTags">Tags (separate da virgola)</label>
        <input id="newTags" type="text" placeholder="marketing, vip, allow" />
      </div>
      <div id="catBox" class="hidden">
        <label for="newCategory">Category ID (1–57)</label>
        <input id="newCategory" type="number" min="1" max="57" placeholder="50" />
      </div>
      <div>
        <label for="newComment">Comment (opzionale)</label>
        <input id="newComment" type="text" placeholder="Motivo / ticket / nota (max 300 char)" />
      </div>
      <div class="row" style="align-items:flex-end">
        <button class="btn primary" id="btnAdd" disabled>➕ Aggiungi</button>
      </div>
    </div>
    <div class="hint" style="margin-top:6px">
      Richiesti <strong>url</strong> + (<strong>tags</strong> <em>oppure</em> <strong>categoryId</strong>), <code>comment</code> facoltativo.
    </div>
  </section>

  <section class="card" id="listCard" style="margin-top:16px">
    <div class="row">
      <h2 style="margin-right:8px">Local Sites</h2>
      <span class="pill" id="pillCount">0 elementi</span>
      <span class="right hint" id="lastFetch"></span>
    </div>
    <div class="sep"></div>
    <div style="overflow:auto">
      <table>
        <thead>
          <tr>
            <th style="width:26%">URL</th>
            <th style="width:20%">Category/Tags</th>
            <th style="width:36%">Comment</th>
            <th class="sticky-right" style="width:18%">Azioni</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </section>
</main>

<div id="toast" class="toast hidden"></div>

<script>
(() => {
  // ====== Stato in memoria (nel browser; backend conserva i segreti) ======
  let whoami = { tenantId: null, dataRegion: null };
  let cache = []; let lastFetchAt = null;
  let filters = { url: '', tagcat: '', comment: '' };

  // ====== Helper UI ======
  const $ = (id) => document.getElementById(id);
  const statusLine = $('statusLine');
  const btnLogin = $('btnLogin');
  const btnFetch = $('btnFetch');
  const btnDownload = $('btnDownload');
  const btnLogout = $('btnLogout');
  const btnAdd = $('btnAdd');
  const tbody = $('tbody');
  const pillCount = $('pillCount');
  const lastFetchSpan = $('lastFetch');
  const toast = $('toast');
  const inMemoryCreds = $('inMemoryCreds');
  const pillUrl = $('pillUrl'), pillTagCat = $('pillTagCat'), pillComment = $('pillComment');

  function showToast(msg, kind = 'ok', timeout = 3500) {
    toast.textContent = msg;
    toast.classList.toggle('danger-toast', kind === 'err');
    toast.classList.remove('hidden');
    setTimeout(() => toast.classList.add('hidden'), timeout);
  }
  function setAuthedUI(on) {
    btnFetch.disabled = !on; btnDownload.disabled = !on; btnLogout.disabled = !on; btnAdd.disabled = !on;
    document.querySelectorAll('#actionsCard, #addCard').forEach(el => {
      if (on) el.removeAttribute('aria-disabled'); else el.setAttribute('aria-disabled', 'true');
    });
  }
  function escapeHtml(s) {
    return (s ?? '').toString().replace(/[&<>\"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function applyFilters(list, f) {
    const u = (f.url || '').toLowerCase(), t = (f.tagcat || '').toLowerCase(), c = (f.comment || '').toLowerCase();
    return list.filter(x => {
      let ok = true;
      if (u) ok = ok && ((x.url || '').toLowerCase().includes(u));
      if (t) {
        const inTags = (x.tags || []).some(tt => (tt || '').toLowerCase().includes(t));
        const inCat = String(x.categoryId ?? '').toLowerCase().includes(t);
        ok = ok && (inTags || inCat);
      }
      if (c) ok = ok && ((x.comment || '').toLowerCase().includes(c));
      return ok;
    });
  }

  function render() {
    const items = applyFilters(cache, filters);
    pillCount.textContent = `${items.length} elemento${items.length !== 1 ? 'i' : ''}`;
    if (lastFetchAt) {
      lastFetchSpan.textContent = `Ultimo aggiornamento: ${new Date(lastFetchAt).toLocaleString()}`;
    }
    pillUrl.style.display = filters.url ? '' : 'none';
    pillTagCat.style.display = filters.tagcat ? '' : 'none';
    pillComment.style.display = filters.comment ? '' : 'none';
    pillUrl.textContent = filters.url ? `URL: ${filters.url}` : '';
    pillTagCat.textContent = filters.tagcat ? `Tag/Cat: ${filters.tagcat}` : '';
    pillComment.textContent = filters.comment ? `Comment: ${filters.comment}` : '';

    tbody.innerHTML = '';
    if (items.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td'); td.colSpan = 4; td.innerHTML = '<span class="muted">Nessun elemento</span>';
      tr.appendChild(td); tbody.appendChild(tr); return;
    }
    for (const it of items) {
      const tr = document.createElement('tr');

      const tdUrl = document.createElement('td');
      tdUrl.innerHTML = `<span class="mono">${escapeHtml(it.url)}</span>`;
      tr.appendChild(tdUrl);

      const tdTagCat = document.createElement('td');
      if (Array.isArray(it.tags) && it.tags.length) {
        const div = document.createElement('div'); div.className = 'tags';
        it.tags.forEach(tag => { const sp = document.createElement('span'); sp.className = 'pill'; sp.textContent = tag; div.appendChild(sp); });
        tdTagCat.appendChild(div);
      } else if (typeof it.categoryId === 'number') {
        tdTagCat.innerHTML = `<span class="pill">categoryId: ${it.categoryId}</span>`;
      } else {
        tdTagCat.innerHTML = `<span class="muted">—</span>`;
      }
      tr.appendChild(tdTagCat);

      const tdComment = document.createElement('td');
      tdComment.className = 'comment-cell';
      tdComment.textContent = it.comment || '';
      if (it.comment) tdComment.title = it.comment;
      tr.appendChild(tdComment);

      const tdAct = document.createElement('td');
      tdAct.className = 'sticky-right actions-cell';
      const delBtn = document.createElement('button');
      delBtn.className = 'btn danger'; delBtn.textContent = 'Elimina';
      delBtn.onclick = () => onDelete(it.id);
      tdAct.appendChild(delBtn);
      tr.appendChild(tdAct);

      tbody.appendChild(tr);
    }
  }

  // ====== API locali ======
  async function apiLogin(clientId, clientSecret) {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret })
    });
    if (!r.ok) { const txt = await r.text().catch(()=>''); throw new Error('Login fallito: ' + (txt || r.status)); }
    return r.json();
  }
  async function apiListLocalSites() {
    const r = await fetch('/api/local-sites?all=true');
    if (!r.ok) { const txt = await r.text().catch(()=>''); throw new Error('Errore lista: ' + (txt || r.status)); }
    return r.json();
  }
  async function apiAddLocalSite(payload) {
    const r = await fetch('/api/local-sites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (r.status !== 201) { const txt = await r.text().catch(()=>''); throw new Error('Errore aggiunta: ' + (txt || r.status)); }
    return r.json();
  }
  async function apiDeleteLocalSite(id) {
    const r = await fetch(`/api/local-sites/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!r.ok) { const txt = await r.text().catch(()=>''); throw new Error('Errore eliminazione: ' + (txt || r.status)); }
  }

  // ====== Event wiring ======
  $('btnSearchUrl').addEventListener('click', () => { setFilter('url', $('searchUrl').value); });
  $('btnSearchTagCat').addEventListener('click', () => { setFilter('tagcat', $('searchTagCat').value); });
  $('btnSearchComment').addEventListener('click', () => { setFilter('comment', $('searchComment').value); });

  $('searchUrl').addEventListener('keyup', e => { if (e.key === 'Enter') $('btnSearchUrl').click(); });
  $('searchTagCat').addEventListener('keyup', e => { if (e.key === 'Enter') $('btnSearchTagCat').click(); });
  $('searchComment').addEventListener('keyup', e => { if (e.key === 'Enter') $('btnSearchComment').click(); });

  function setFilter(kind, value) {
    filters = Object.assign({}, filters, { [kind]: (value || '').trim() });
    render();
  }
  $('btnClear').addEventListener('click', () => {
    $('searchUrl').value = ''; $('searchTagCat').value = ''; $('searchComment').value = '';
    filters = { url: '', tagcat: '', comment: '' }; render();
  });

  btnLogin.addEventListener('click', async () => {
    try {
      const clientId = $('clientId').value.trim(); const clientSecret = $('clientSecret').value.trim();
      if (!clientId || !clientSecret) throw new Error('Inserisci Client ID e Client Secret');
      inMemoryCreds.value = JSON.stringify({ clientId, clientSecret: '***' });

      statusLine.textContent = 'Autenticazione…';
      const data = await apiLogin(clientId, clientSecret);
      if (!data.ok) throw new Error('Login fallito');
      whoami.tenantId = data.tenantId; whoami.dataRegion = data.dataRegion;
      statusLine.textContent = `Autenticato • Tenant ${String(whoami.tenantId||'').slice(0,8)}… • ${whoami.dataRegion}`;
      setAuthedUI(true); showToast('Accesso effettuato');
    } catch (e) {
      setAuthedUI(false); statusLine.textContent = 'Non autenticato';
      showToast(e.message || String(e), 'err', 6000);
    }
  });

  $('btnLogout').addEventListener('click', () => {
    // lato server restano credenziali in RAM; qui resettiamo UI
    whoami = { tenantId: null, dataRegion: null };
    cache = []; lastFetchAt = null; filters = { url: '', tagcat: '', comment: '' };
    $('clientId').value = ''; $('clientSecret').value = ''; inMemoryCreds.value = '';
    setAuthedUI(false); statusLine.textContent = 'Non autenticato'; render(); showToast('Logout eseguito');
  });

  $('btnFetch').addEventListener('click', async () => {
    try {
      $('btnFetch').disabled = true; $('btnFetch').textContent = '⏳ Aggiorno…';
      const data = await apiListLocalSites();
      cache = Array.isArray(data.items) ? data.items : []; lastFetchAt = Date.now(); render(); showToast('Lista aggiornata');
    } catch (e) { showToast(e.message || String(e), 'err', 6000); }
    finally { $('btnFetch').disabled = false; $('btnFetch').textContent = '🔄 Aggiorna lista'; }
  });

  // Toggle modalità aggiunta
  document.querySelectorAll('input[name="mode"]').forEach(r => {
    r.addEventListener('change', () => {
      const mode = document.querySelector('input[name="mode"]:checked').value;
      if (mode === 'tags') { $('tagsBox').classList.remove('hidden'); $('catBox').classList.add('hidden'); }
      else { $('catBox').classList.remove('hidden'); $('tagsBox').classList.add('hidden'); }
    });
  });

  $('btnAdd').addEventListener('click', async () => {
    try {
      const url = $('newUrl').value.trim(); if (!url) { showToast('URL obbligatorio', 'err'); return; }
      const mode = document.querySelector('input[name="mode"]:checked').value;
      let tags = []; let categoryId = undefined;
      if (mode === 'tags') {
        tags = $('newTags').value.split(',').map(s => s.trim()).filter(Boolean);
        if (tags.length === 0) { showToast('Inserisci almeno un tag oppure usa Category ID', 'err'); return; }
      } else {
        const v = Number($('newCategory').value);
        if (!Number.isInteger(v) || v < 1 || v > 57) { showToast('Category ID deve essere tra 1 e 57', 'err'); return; }
        categoryId = v;
      }
      const comment = $('newComment').value.trim();

      $('btnAdd').disabled = true; $('btnAdd').textContent = '⏳ Aggiungo…';
      const res = await apiAddLocalSite({ url, tags, categoryId, comment });
      const created = res.item;
      cache.unshift(created); render(); showToast('Aggiunto: ' + (created?.url || url));
      $('newUrl').value = ''; $('newTags').value = ''; $('newCategory').value = ''; $('newComment').value = '';
    } catch (e) { showToast(e.message || String(e), 'err', 6000); }
    finally { $('btnAdd').disabled = false; $('btnAdd').textContent = '➕ Aggiungi'; }
  });

  function onDelete(id) {
    if (!confirm('Confermi eliminazione?')) return;
    apiDeleteLocalSite(id).then(() => {
      cache = cache.filter(x => x.id !== id); render(); showToast('Elemento eliminato');
    }).catch(async r => {
      showToast(r.message || String(r), 'err', 6000);
    });
  }

  // Primo render
  render();
})();
</script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return Response(INDEX_HTML, mimetype="text/html")

if __name__ == "__main__":
    # Avvio locale
    # Nota: debug=False per evitare leak di variabili in error page,
    # ma durante sviluppo puoi metterlo True.
    app.run(host="127.0.0.1", port=5000, debug=False)
