# Wingman server — v3.7.0
# Storage: Postgres (DATABASE_URL). Notion is used ONLY by the one-time import + verify
# jobs under /api/admin/*, server-side, and is never proxied for the browser.
import os, json, re, urllib.request, urllib.error, secrets, hashlib, time, threading, queue, base64, traceback, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote, urlencode
from datetime import datetime, timezone, timedelta

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb
    from psycopg_pool import ConnectionPool
    _PSYCOPG_IMPORT_ERROR = ""
except Exception as _imp_err:  # server still boots and reports the problem on /api/*
    psycopg = None
    _PSYCOPG_IMPORT_ERROR = str(_imp_err)

SERVER_VERSION      = "3.7.0"
HTML_FILE           = "Wingman.html"
PORT                = int(os.environ.get("PORT", 3747))
DIR                 = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL        = os.environ.get("DATABASE_URL", "")
NOTION_TOKEN        = os.environ.get("NOTION_TOKEN", "")   # import/verify only; unset after cutover
ANTHROPIC_KEY       = os.environ.get("ANTHROPIC_KEY", "")
GOOGLE_CLIENT_ID    = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET= os.environ.get("GOOGLE_CLIENT_SECRET", "")
BASE_URL            = os.environ.get("BASE_URL", "https://vigilant-youthfulness-production-896b.up.railway.app")
REDIRECT_URI        = BASE_URL + "/auth/callback"
GORGIAS_DOMAIN      = os.environ.get("GORGIAS_DOMAIN", "freedomgrooming.gorgias.com")
GORGIAS_USERNAME    = os.environ.get("GORGIAS_USERNAME", "")
GORGIAS_API_KEY     = os.environ.get("GORGIAS_API_KEY", "")
EMERGENCY_PIN       = os.environ.get("EMERGENCY_PIN", "")
# Who may sign in (as Full) while qa_users is still empty, i.e. before the import has run.
BOOTSTRAP_ADMINS    = {e.strip().lower() for e in os.environ.get("BOOTSTRAP_ADMINS", "drew@myfreebird.com").split(",") if e.strip()}

# Source Notion databases (import/verify only)
NOTION_DBS = {
    "qa_users":      os.environ.get("QA_USERS_DB_ID",             "3744e96c994180c9b8adcec4048bc6fb"),
    "tickets":       os.environ.get("NOTION_TICKETS_DB_ID",       "3564e96c9941800786f6e190e6f47505"),
    "config":        os.environ.get("NOTION_CONFIG_DB_ID",        "3574e96c994180c08a40f31e89db80ce"),
    "reports":       os.environ.get("NOTION_REPORTS_DB_ID",       "3684e96c994180db8929c67f306c554a"),
    "calib_rounds":  os.environ.get("NOTION_CALIB_ROUNDS_DB_ID",  "e1ef82f8aeea44adbcd7502f2ac6f62f"),
    "calib_reviews": os.environ.get("NOTION_CALIB_REVIEWS_DB_ID", "61622a92a67a45468c6b1774595c0d59"),
}

ALLOWED_DOMAINS     = {"myfreebird.com", "freedom-grooming.com"}

# SECURITY: /proxy may only forward to these hosts (prevents SSRF / open-relay abuse).
# api.notion.com removed in v3.0.0 — the browser never talks to Notion.
PROXY_ALLOWED_HOSTS = {"api.anthropic.com"}

# In-memory session store: token -> {email, name, exp}
SESSIONS = {}
SESSION_TTL = 60 * 60 * 24 * 7  # 7 days
SESSIONS_LOCK = threading.Lock()

# In-memory OAuth state store: state -> timestamp (prevents CSRF)
OAUTH_STATES = {}
OAUTH_STATE_TTL = 300  # 5 minutes

ROLE_RANK = {"full": 2, "edit": 1}
def role_rank(role):
    return ROLE_RANK.get((role or "").lower(), 0)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

# ── Emergency login page HTML ──────────────────────────────────────────────────
EMERGENCY_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FG QA — Emergency Access</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0f0f0f;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }}
  .card {{
    background: #1a1a1a;
    border: 1px solid #2a2a2a;
    border-radius: 12px;
    padding: 40px;
    width: 360px;
  }}
  .logo {{
    font-size: 12px;
    color: #444;
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-bottom: 28px;
  }}
  h2 {{
    color: #e0e0e0;
    font-size: 20px;
    font-weight: 600;
    margin-bottom: 8px;
  }}
  p {{
    color: #555;
    font-size: 13px;
    margin-bottom: 28px;
    line-height: 1.5;
  }}
  label {{
    display: block;
    color: #666;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 6px;
  }}
  input {{
    width: 100%;
    background: #111;
    border: 1px solid #2a2a2a;
    border-radius: 8px;
    color: #e0e0e0;
    font-size: 14px;
    padding: 10px 14px;
    margin-bottom: 20px;
    outline: none;
    transition: border-color 0.2s;
  }}
  input:focus {{ border-color: #444; }}
  button {{
    width: 100%;
    background: #222;
    border: 1px solid #333;
    border-radius: 8px;
    color: #ccc;
    font-size: 14px;
    padding: 11px;
    cursor: pointer;
    transition: background 0.2s, color 0.2s;
  }}
  button:hover {{ background: #2a2a2a; color: #e0e0e0; }}
  .error {{
    background: #1e0f0f;
    border: 1px solid #4a1f1f;
    border-radius: 8px;
    color: #e06060;
    font-size: 13px;
    padding: 10px 14px;
    margin-bottom: 20px;
  }}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Freedom Grooming &nbsp;·&nbsp; QA Tool</div>
  <h2>Emergency Access</h2>
  <p>Use this only if Google SSO is unavailable. Enter your work email and the emergency PIN.</p>
  {error_block}
  <form method="POST" action="/emergency">
    <label>Work Email</label>
    <input type="email" name="email" placeholder="you@myfreebird.com" required autocomplete="off" autofocus>
    <label>Emergency PIN</label>
    <input type="password" name="pin" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required autocomplete="off">
    <button type="submit">Access QA Tool</button>
  </form>
</div>
</body>
</html>"""

def render_emergency(error=None, status=200):
    error_block = f'<div class="error">{error}</div>' if error else ""
    html = EMERGENCY_HTML.replace("{error_block}", error_block).encode()
    return html, status

# ── Contact reason options (legacy hardcoded list; v3.2.0 injects the LIVE list — see
#    cr_options_for_inject(). These constants are no longer read; kept for reference) ──

CR_L1_OPTIONS = [
    "Cancel",
    "Order Issue",
    "Order Status",
    "Other",
    "Subscription",
    "Troubleshooting",
    "Update Order"
]

CR_L2_OPTIONS = {
    "Cancel": [
        "Cancel 1st Product Order",
        "Subscription (Aware)",
        "Subscription (Unaware)",
        "Subscription Aware",
        "Subscription Order",
        "Subscription Unaware"
    ],
    "Order Issue": [
        "CX Wrong Item / Order",
        "FB Wrong Item / Order",
        "Missing Item From Kit",
        "Missing Item From Order",
        "Package Damaged / Damaged Upon Arrival",
        "Received Unsatisfactory Product",
        "Received Used Product",
        "Return Request"
    ],
    "Order Status": [
        "Delays, but Not Lost",
        "Delivered, Not Received",
        "International (Delays, but Not Lost)",
        "International (No Delays)",
        "Lost in Transit",
        "Never Shipped",
        "No Delays",
        "Returned to Sender",
        "Wrong Address"
    ],
    "Other": [
        "General Order Question",
        "General Product Question",
        "Influencer/Job Inquiry",
        "Negative Feedback",
        "Other",
        "Payment/Charge Issues",
        "Positive Feedback",
        "Promo Request/Issue",
        "Social General/Tagging",
        "System Notification",
        "Update Account",
        "Wholesale"
    ],
    "Subscription": [
        "Change Address",
        "Change Frequency",
        "Change Product",
        "Skip Order"
    ],
    "Troubleshooting": [
        "Broken Blade / Attachment",
        "Never worked (new device)",
        "Stopped Working",
        "Will Not Charge",
        "Won't turn OFF"
    ],
    "Update Order": [
        "Add / Remove / Change Item",
        "Change Address"
    ]
}

# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE
# ══════════════════════════════════════════════════════════════════════════════
POOL = None
DB_ERROR = ""

def db_init():
    global POOL, DB_ERROR
    if psycopg is None:
        DB_ERROR = "psycopg not installed: " + _PSYCOPG_IMPORT_ERROR
        return
    if not DATABASE_URL:
        DB_ERROR = "DATABASE_URL is not set"
        return
    try:
        POOL = ConnectionPool(DATABASE_URL, min_size=1, max_size=int(os.environ.get("DB_POOL_MAX", "10")),
                              kwargs={"row_factory": dict_row}, open=True, timeout=30)
        with open(os.path.join(DIR, "schema.sql"), "r", encoding="utf-8") as f:
            schema_sql = f.read()
        with POOL.connection() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(4247001)")
            conn.execute(schema_sql)
        DB_ERROR = ""
        print("[DB] Connected, schema applied")
    except Exception as e:
        POOL = None
        DB_ERROR = f"{type(e).__name__}: {e}"
        print(f"[DB] INIT FAILED: {DB_ERROR}")

def migrate_autofail_zero():
    """v3.5.0 one-time migration: autofailed audits score 0%. Category scores (scores jsonb) and total_points are
    untouched, so the rubric % is always recoverable. Marked done in app_state so it runs once."""
    if POOL is None or (state_get("migration_autofail_zero") or {}).get("done"):
        return 0
    n = db_exec("""UPDATE tickets SET ai_score = 0, final_score = 0, final_passed = false,
                       updated_at = now(), app_updated_at = now()
                   WHERE autofail AND (COALESCE(ai_score, 0) <> 0 OR COALESCE(final_score, 0) <> 0 OR final_passed)""")
    state_set("migration_autofail_zero", {"done": True, "at": now_iso(), "rows": n})
    print(f"[Migration] autofail = 0%: {n} audit(s) updated")
    return n

# ── v3.6.1 one-time repair: autofails stored as {fail:false,...} objects ──────────
# The AI sometimes returned every autofail condition with a verdict. Any non-empty list counted as an autofail, so
# tickets where the AI said NO autofail applied were marked autofailed (0% since v3.5.0). This keeps only conditions
# that apply, as text; when none apply it clears the autofail and restores the real score. Manual autofails untouched.
def _af_text(a):
    if a is None: return ""
    if isinstance(a, str): return a.strip()
    if isinstance(a, dict):
        for k in ("description", "condition", "name", "reason", "label", "text"):
            if a.get(k): return str(a[k]).strip()
        return json.dumps(a)
    return str(a)

def _af_applies(a):
    if a is None: return False
    if isinstance(a, str):
        t = a.strip().lower(); return bool(t) and t not in ("none", "n/a", "na", "no", "false", "[]")
    if isinstance(a, dict):
        for k in ("fail", "failed", "triggered", "applies", "autofail", "isAutofail", "value", "result"):
            if k in a:
                v = a[k]; return v is True or bool(re.fullmatch(r"(true|yes|fail|failed|y)", str(v), re.I))
        return True
    return bool(a)

def normalize_autofails(arr):
    out = []
    for a in (arr if isinstance(arr, list) else []):
        if _af_applies(a):
            t = _af_text(a)
            if t and t not in out: out.append(t)
    return out

def _score_val(v):
    if not v or v == "NA": return None
    m = re.search(r"\(([\d.]+)\)", str(v)); return float(m.group(1)) if m else None

def _calc_pct(scores, matrix):
    pts = mx = 0.0
    for c in matrix:
        sv = _score_val((scores or {}).get(c.get("id")))
        if sv is not None: pts += sv; mx += float(c.get("max") or 0)
    return None if mx == 0 else round(pts / mx * 100)

def _norm_dispute(val, cat):
    """Twin of normalizeDisputeScore(): bare labels ('YES','Pass','Miss') -> 'LEVEL (points)'."""
    if not val or re.search(r"\([\d.]+\)", str(val)): return val
    up = str(val).upper()
    for l in cat.get("levels") or []:
        lv = str(l.get("level", "")).upper()
        if lv == up or (up == "PASS" and lv.startswith("YES")) or (up == "MISS" and lv.startswith("NO")):
            if l.get("points") is not None: return f"{l['level']} ({l['points']})"
    return val

def _disputed_pct(scores, disputes, matrix):
    merged = {}
    for c in matrix:
        d = (disputes or {}).get(c["id"])
        use = isinstance(d, dict) and (d.get("status") == "approved" or not d.get("status"))
        merged[c["id"]] = _norm_dispute(d.get("finalScore"), c) if use else (scores or {}).get(c["id"], "")
    return _calc_pct(merged, matrix)

def repair_autofail_objects():
    if POOL is None or (state_get("migration_autofail_objects") or {}).get("done"):
        return 0
    m = db_one("SELECT value FROM config WHERE key='matrix'")
    matrix = (m or {}).get("value") if m else None
    if not isinstance(matrix, list) or not matrix:
        print("[Migration] autofail objects: no saved matrix, skipped (will retry next start)"); return 0
    rows = db_all("""SELECT id, ticket_id, autofail, autofail_manual, autofails, scores, disputes FROM tickets
                     WHERE jsonb_typeof(autofails) = 'array' AND jsonb_array_length(autofails) > 0
                       AND EXISTS (SELECT 1 FROM jsonb_array_elements(autofails) e WHERE jsonb_typeof(e) <> 'string')""")
    cleared, cleaned = [], []
    with POOL.connection() as conn:
        for r in rows:
            norm = normalize_autofails(r["autofails"])
            if r["autofail_manual"] or norm:
                # keep the autofail (manual, or a condition really applied) but store the conditions as text
                conn.execute("UPDATE tickets SET autofails=%s, updated_at=now(), app_updated_at=now() WHERE id=%s", (Jsonb(norm if norm else [_af_text(a) for a in r["autofails"]]), r["id"]))
                cleaned.append(r["ticket_id"]); continue
            ai = _calc_pct(r["scores"], matrix) or 0
            fin = _disputed_pct(r["scores"], r["disputes"], matrix)
            fin = ai if fin is None else fin
            conn.execute("""UPDATE tickets SET autofail=false, autofails='[]'::jsonb, ai_score=%s, final_score=%s,
                              ai_passed=%s, final_passed=%s, updated_at=now(), app_updated_at=now() WHERE id=%s""",
                         (ai, fin, ai >= 85, fin >= 85, r["id"]))
            cleared.append(r["ticket_id"])
    state_set("migration_autofail_objects", {"done": True, "at": now_iso(), "cleared": cleared, "cleanedOnly": cleaned})
    print(f"[Migration] autofail objects: {len(cleared)} false autofail(s) cleared + scores restored, {len(cleaned)} cleaned to text")
    return len(cleared)

def db_all(sql, params=None):
    with POOL.connection() as conn:
        return conn.execute(sql, params).fetchall()

def db_one(sql, params=None):
    with POOL.connection() as conn:
        return conn.execute(sql, params).fetchone()

def db_exec(sql, params=None):
    with POOL.connection() as conn:
        return conn.execute(sql, params).rowcount

def state_get(key, default=None):
    r = db_one("SELECT value FROM app_state WHERE key=%s", (key,))
    return r["value"] if r else default

def state_set(key, value):
    db_exec("""INSERT INTO app_state (key,value,updated_at) VALUES (%s,%s,now())
               ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()""", (key, Jsonb(value)))

def cutover_state():
    return state_get("cutover", {"done": False}) or {"done": False}

def is_uuid(s):
    try:
        uuid.UUID(str(s)); return True
    except Exception:
        return False

def normalize_agent_name(s):
    """Server twin of the client's normalizeAgentName()."""
    return re.sub(r"\s+", " ", (s or "").replace("\u00a0", " ")).strip()

# ══════════════════════════════════════════════════════════════════════════════
#  USERS / AUTH
# ══════════════════════════════════════════════════════════════════════════════

def user_row_to_api(r):
    return {
        "id": str(r["id"]), "rowId": str(r["id"]),
        "email": r["email"], "name": r["name"] or r["email"].split("@")[0], "role": r["role"] or "view",
        "active": r["active"], "assignAudits": r["assign_audits"], "excludeTickets": r["exclude_tickets"],
        "notes": r["notes"] or "", "agentName": r["name"] or "",
    }

def users_count():
    if POOL is None:
        return 0
    return db_one("SELECT count(*) AS n FROM qa_users WHERE NOT archived")["n"]

def resolve_user(email):
    """Authoritative user record for an email, or None. Bootstrap admin only while qa_users is empty."""
    if POOL is None or not email:
        return None
    em = email.lower().strip()
    r = db_one("SELECT * FROM qa_users WHERE lower(email)=%s AND NOT archived", (em,))
    if r:
        u = user_row_to_api(r); u["bootstrap"] = False
        return u
    if em in BOOTSTRAP_ADMINS and users_count() == 0:
        return {"id": None, "rowId": None, "email": em, "name": em.split("@")[0].title() + " (bootstrap)",
                "role": "full", "active": True, "assignAudits": False, "excludeTickets": False,
                "notes": "", "agentName": "", "bootstrap": True}
    return None

def find_user_by_email(email):
    """Emergency login: active users only (strict, no domain fallback)."""
    u = resolve_user(email)
    return u if (u and u.get("active") is not False) else None

def inject_env(html: bytes) -> bytes:
    # SECURITY: ANTHROPIC_KEY is intentionally NOT exposed to the client. The /proxy
    # handler injects it server-side, so it never reaches the browser.
    env = {
        "GOOGLE_CLIENT_ID":   GOOGLE_CLIENT_ID,
        "BASE_URL":           BASE_URL,
        "GORGIAS_DOMAIN":     GORGIAS_DOMAIN,
        "GORGIAS_CONFIGURED": bool(GORGIAS_USERNAME and GORGIAS_API_KEY),
        "STORAGE":            "postgres",
    }
    cr_l1, cr_l2 = cr_options_for_inject()   # live Contact Reason options (hardcoded fallback)
    snippet = (
        "<script>"
        f"window.__ENV__={json.dumps(env)};"
        f"window.__CR_L1_OPTIONS={json.dumps(cr_l1)};"
        f"window.__CR_L2_OPTIONS={json.dumps(cr_l2)};"
        "</script>"
    )
    return html.replace(b"</head>", snippet.encode() + b"</head>", 1)

def get_version():
    try:
        with open(os.path.join(DIR, HTML_FILE), "r", encoding="utf-8") as f:
            for line in f:
                if "Version:" in line:
                    return line.strip()
        return "unknown"
    except:
        return "error reading file"

def google_get_token(code):
    data = urlencode({
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }).encode()
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())

def google_get_userinfo(access_token):
    req = urllib.request.Request(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())

def create_session(email, name, via="google", picture=""):
    token = secrets.token_urlsafe(32)
    # Google profile photo URL (v3.1.0). Only https URLs are kept; emergency logins have none.
    pic = picture if isinstance(picture, str) and picture.startswith("https://") else ""
    with SESSIONS_LOCK:
        SESSIONS[token] = {
            "email":   email.lower().strip(),
            "name":    name,
            "via":     via,
            "picture": pic,
            "exp":     time.time() + SESSION_TTL
        }
        # Clean expired sessions opportunistically
        expired = [k for k, v in SESSIONS.items() if v["exp"] < time.time()]
        for k in expired:
            del SESSIONS[k]
    return token

def verify_session(token):
    with SESSIONS_LOCK:
        session = SESSIONS.get(token)
        if not session:
            return None
        if session["exp"] < time.time():
            del SESSIONS[token]
            return None
        return session

def parse_form(raw: bytes) -> dict:
    """Parse application/x-www-form-urlencoded body."""
    out = {}
    for pair in raw.decode(errors="replace").split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[unquote(k.replace("+", " "))] = unquote(v.replace("+", " "))
    return out

# ══════════════════════════════════════════════════════════════════════════════
#  VALUE COERCION + TICKET FIELD MAP
# ══════════════════════════════════════════════════════════════════════════════

class ApiError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg); self.status = status; self.msg = msg

def c_text(v):
    if v is None: return ""
    if isinstance(v, (dict, list)): return json.dumps(v)
    return str(v)

def c_num(v):
    if v is None or v == "": return None
    try:
        return float(v)
    except Exception:
        raise ApiError(400, f"not a number: {v!r}")

def c_int(v):
    if v is None or v == "": return None
    try:
        return int(round(float(v)))
    except Exception:
        raise ApiError(400, f"not an integer: {v!r}")

def c_bool(v):
    if isinstance(v, str): return v.lower() in ("true", "1", "yes")
    return bool(v)

def c_json(v, default):
    """Accept an object or a JSON string. A string that doesn't parse is a client bug -> 400."""
    if v is None: return default
    if isinstance(v, str):
        if v.strip() == "": return default
        try:
            return json.loads(v)
        except Exception:
            raise ApiError(400, "invalid JSON string in field")
    return v

# api key -> (column, kind). kinds: text num int bool jobj jarr json
TICKET_FIELDS = {
    "ticketId": ("ticket_id", "text"), "agentName": ("agent_name", "text"), "reviewer": ("auditor", "text"),
    "week": ("week", "text"), "createdDate": ("created_date", "text"), "contactReason": ("contact_reason", "text"),
    "subject": ("subject", "text"), "ticketUrl": ("ticket_url", "text"),
    "aiScore": ("ai_score", "num"), "finalScore": ("final_score", "num"),
    "aiPassed": ("ai_passed", "bool"), "finalPassed": ("final_passed", "bool"), "hasDisputes": ("has_disputes", "bool"),
    "reviewed": ("reviewed", "bool"), "reviewedBy": ("reviewed_by", "text"), "reviewedAt": ("reviewed_at", "text"),
    "reviewerNotes": ("reviewer_notes", "text"), "autofail": ("autofail", "bool"), "autofailManual": ("autofail_manual", "bool"),
    "scores": ("scores", "jobj"), "disputes": ("disputes", "jobj"), "justifications": ("justifications", "jobj"),
    "autofails": ("autofails", "jarr"), "notesHistory": ("notes_history", "jobj"), "reopenHistory": ("reopen_history", "jarr"),
    "reauditHistory": ("reaudit_history", "jarr"),
    "comments": ("comments", "text"), "transcript": ("transcript", "text"), "savedAt": ("saved_at", "text"),
    "auditType": ("audit_type", "text"), "messageCount": ("message_count", "int"), "agentMessageCount": ("agent_message_count", "int"),
    "deleted": ("deleted", "bool"), "deletedBy": ("deleted_by", "text"), "deletedAt": ("deleted_at", "text"),
    "deleteReason": ("delete_reason", "text"),
    "unlockedOverride": ("unlocked_override", "bool"), "unlockedBy": ("unlocked_by", "text"),
    "unlockedAt": ("unlocked_at", "text"), "unlockReason": ("unlock_reason", "text"),
    "auditWeek": ("audit_week", "text"), "totalPoints": ("total_points", "num"), "maxPoints": ("max_points", "num"),
    "replacedFor": ("replaced_for", "text"), "customerEmail": ("customer_email", "text"),
    "aiMeta": ("ai_meta", "json"), "ctfAsScored": ("ctf_as_scored", "json"), "matrixVersion": ("matrix_version", "int"),
}
# Agents (view/agent role) may only change these, and only on their own tickets.
AGENT_WRITABLE = {"disputes", "hasDisputes"}

NOTE_CATS = ["ctf", "empathy", "fcr", "product", "order", "returns", "promo", "retention"]

def coerce(kind, v):
    if kind == "text": return c_text(v)
    if kind == "num":  return c_num(v)
    if kind == "int":  return c_int(v)
    if kind == "bool": return c_bool(v)
    if kind == "jobj": return Jsonb(c_json(v, {}))
    if kind == "jarr": return Jsonb(c_json(v, []))
    if kind == "json":
        val = c_json(v, None)
        return Jsonb(val) if val is not None else None
    raise ApiError(500, "bad kind " + kind)

def format_note(j):
    """Server twin of the client's formatNotes(): full text, no cap."""
    if not isinstance(j, dict): return ""
    out = j.get("reason") or j.get("r") or ""
    imp = j.get("improve") or j.get("i") or ""
    if imp and imp != "null":
        out = f"{out} | ↑ {imp}"
    return str(out)

def ticket_payload_to_cols(body, allowed=None):
    cols = {}
    for k, v in (body or {}).items():
        if k not in TICKET_FIELDS:
            continue
        if allowed is not None and k not in allowed:
            raise ApiError(403, f"field not writable for your role: {k}")
        col, kind = TICKET_FIELDS[k]
        cols[col] = coerce(kind, v)
    # Per-category notes are derived from justifications on every write (legacy/readable copy)
    if "justifications" in cols:
        just = cols["justifications"].obj or {}
        for cat in NOTE_CATS:
            cols[f"{cat}_notes"] = format_note(just.get(cat) if isinstance(just, dict) else None)
    return cols

TICKET_LIST_COLS = """id, ticket_id, agent_name, auditor, week, created_date, contact_reason, subject, ticket_url,
  ai_score, final_score, ai_passed, final_passed, has_disputes, reviewed, reviewed_by, reviewed_at, reviewer_notes,
  autofail, autofail_manual, scores, disputes, justifications, autofails, notes_history, reopen_history, reaudit_history,
  comments, transcript, saved_at, audit_type, message_count, agent_message_count, deleted, deleted_by, deleted_at,
  delete_reason, unlocked_override, unlocked_by, unlocked_at, unlock_reason, audit_week, total_points, max_points,
  replaced_for, customer_email, ai_meta, ctf_as_scored, matrix_version, snapshot_status, notion_page_id"""

def _js(v, default):
    return json.dumps(v if v is not None else default)

def ticket_row_to_api(r):
    """Same shape v2's loadTicketsFromNotion() handed to parseNotionRow() — JSON fields as strings."""
    return {
        "id": str(r["id"]), "pageId": str(r["id"]),
        "ticketId": r["ticket_id"], "agentName": r["agent_name"], "reviewer": r["auditor"], "week": r["week"],
        "createdDate": r["created_date"], "contactReason": r["contact_reason"], "subject": r["subject"],
        "ticketUrl": r["ticket_url"],
        "aiScore": r["ai_score"] if r["ai_score"] is not None else 0,
        "finalScore": r["final_score"] if r["final_score"] is not None else 0,
        "aiPassed": r["ai_passed"], "finalPassed": r["final_passed"], "hasDisputes": r["has_disputes"],
        "reviewed": r["reviewed"], "reviewedBy": r["reviewed_by"], "reviewedAt": r["reviewed_at"],
        "reviewerNotes": r["reviewer_notes"], "autofail": r["autofail"], "autofailManual": r["autofail_manual"],
        "scoresJSON": _js(r["scores"], {}), "disputesJSON": _js(r["disputes"], {}),
        "justificationsJSON": _js(r["justifications"], {}), "autofailsJSON": _js(r["autofails"], []),
        "notesHistoryJSON": _js(r["notes_history"], {}), "reopenHistoryJSON": _js(r["reopen_history"], []),
        "reauditHistory": _js(r["reaudit_history"], []),
        "comments": r["comments"], "transcript": r["transcript"], "savedAt": r["saved_at"],
        "auditType": r["audit_type"], "messageCount": r["message_count"], "agentMessageCount": r["agent_message_count"],
        "deleted": r["deleted"], "deletedBy": r["deleted_by"], "deletedAt": r["deleted_at"], "deleteReason": r["delete_reason"],
        "unlockedOverride": r["unlocked_override"], "unlockedBy": r["unlocked_by"], "unlockedAt": r["unlocked_at"],
        "unlockReason": r["unlock_reason"],
        "auditWeek": r["audit_week"], "totalPoints": r["total_points"], "maxPoints": r["max_points"],
        "replacedFor": r["replaced_for"], "customerEmail": r["customer_email"],
        "aiMeta": r["ai_meta"], "ctfAsScored": r["ctf_as_scored"], "matrixVersion": r["matrix_version"],
        "snapshotStatus": r["snapshot_status"], "imported": bool(r.get("notion_page_id")),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  GORGIAS SNAPSHOT WORKER  (full GET /api/tickets/{id} per saved audit)
# ══════════════════════════════════════════════════════════════════════════════
SNAP_Q = queue.Queue()
SNAP_PACE_SEC = float(os.environ.get("SNAPSHOT_PACE_SEC", "1.2"))
SNAP_MAX_ATTEMPTS = 5

def gorgias_get(path):
    creds = base64.b64encode(f"{GORGIAS_USERNAME}:{GORGIAS_API_KEY}".encode()).decode()
    req = urllib.request.Request(f"https://{GORGIAS_DOMAIN}/api{path}", headers={
        "Authorization": f"Basic {creds}", "Accept": "application/json",
        "User-Agent": "FG-QA-Tool/3.0 (internal; snapshot)"})
    resp = urllib.request.urlopen(req, timeout=45)
    return json.loads(resp.read())

def _ts(v):
    if not v: return None
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except Exception:
        return None

def _cf_value(cf, fid):
    v = (cf or {}).get(str(fid))
    if isinstance(v, dict): v = v.get("value", v.get("text"))
    return None if v is None else str(v)

def enqueue_snapshot(audit_id, delay=0):
    if delay > 0:
        t = threading.Timer(delay, lambda: SNAP_Q.put(str(audit_id)))
        t.daemon = True
        t.start()
    else:
        SNAP_Q.put(str(audit_id))

def _snapshot_fail(row, err):
    attempts = (row["snapshot_attempts"] or 0) + 1
    db_exec("UPDATE tickets SET snapshot_status='failed', snapshot_attempts=%s, snapshot_error=%s WHERE id=%s",
            (attempts, err[:500], row["id"]))
    print(f"[Snapshot] #{row['ticket_id']} failed ({attempts}/{SNAP_MAX_ATTEMPTS}): {err}")
    if attempts < SNAP_MAX_ATTEMPTS:
        enqueue_snapshot(row["id"], delay=60 * attempts)

def process_snapshot(audit_id):
    row = db_one("SELECT id, ticket_id, snapshot_attempts, snapshot_status FROM tickets WHERE id=%s", (audit_id,))
    if not row or row["snapshot_status"] == "ok":
        return
    tid = (row["ticket_id"] or "").strip()
    if not tid.isdigit():
        db_exec("UPDATE tickets SET snapshot_status='skipped', snapshot_error='ticket id is not numeric' WHERE id=%s", (audit_id,))
        return
    if not (GORGIAS_USERNAME and GORGIAS_API_KEY):
        db_exec("UPDATE tickets SET snapshot_status='failed', snapshot_error='Gorgias not configured' WHERE id=%s", (audit_id,))
        return
    try:
        raw = gorgias_get(f"/tickets/{tid}")
    except urllib.error.HTTPError as e:
        if e.code == 429:
            wait = float(e.headers.get("Retry-After") or 20)
            print(f"[Snapshot] 429 on #{tid}, backing off {wait}s")
            time.sleep(min(wait, 60))
            enqueue_snapshot(audit_id)
            return
        if e.code == 404:
            db_exec("UPDATE tickets SET snapshot_status='not_found', snapshot_error='404 from Gorgias' WHERE id=%s", (audit_id,))
            return
        _snapshot_fail(row, f"HTTP {e.code}")
        return
    except Exception as e:
        _snapshot_fail(row, f"{type(e).__name__}: {e}")
        return

    if isinstance(raw, dict) and raw.get("requester") == raw.get("customer"):
        raw.pop("requester", None)   # exact duplicate of customer (~100 KB); saves ~25%
    cf = raw.get("custom_fields") or {}
    cf_flat = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in cf.items()}
    assignee = raw.get("assignee_user") or {}
    tags = [t.get("name") for t in (raw.get("tags") or []) if isinstance(t, dict) and t.get("name")]
    msgs = raw.get("messages")
    with POOL.connection() as conn:
        conn.execute("""INSERT INTO ticket_snapshots
            (audit_id, gorgias_ticket_id, raw, status, channel, via, priority, language, assignee_user_id,
             assignee_email, assignee_name, assignee_team_id, tags, custom_fields, cf_contact_reason, cf_product,
             cf_ticket_resolution, cf_additional_resolution, cf_7630, created_datetime, opened_datetime,
             closed_datetime, last_message_datetime, message_count, customer_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (audit_id, raw.get("id"), Jsonb(raw), raw.get("status"), raw.get("channel"), raw.get("via"),
             raw.get("priority"), raw.get("language"), raw.get("assignee_user_id"), assignee.get("email"),
             assignee.get("name"), raw.get("assignee_team_id"), tags, Jsonb(cf_flat),
             _cf_value(cf, 9969), _cf_value(cf, 5807), _cf_value(cf, 11375), _cf_value(cf, 11421), _cf_value(cf, 7630),
             _ts(raw.get("created_datetime")), _ts(raw.get("opened_datetime")), _ts(raw.get("closed_datetime")),
             _ts(raw.get("last_message_datetime")), len(msgs) if isinstance(msgs, list) else None,
             (raw.get("customer") or {}).get("id")))
        conn.execute("UPDATE tickets SET snapshot_status='ok', snapshot_error='' WHERE id=%s", (audit_id,))

def snapshot_worker():
    while True:
        audit_id = SNAP_Q.get()
        try:
            if POOL is not None:
                process_snapshot(audit_id)
        except Exception as e:
            print(f"[Snapshot] worker error on {audit_id}: {e}")
            traceback.print_exc()
        time.sleep(SNAP_PACE_SEC)

def requeue_pending_snapshots():
    if POOL is None: return 0
    rows = db_all("""SELECT id FROM tickets WHERE snapshot_status='pending'
                     OR (snapshot_status='failed' AND snapshot_attempts < %s)""", (SNAP_MAX_ATTEMPTS,))
    for r in rows:
        enqueue_snapshot(r["id"])
    return len(rows)

# ── PII censoring for the UI (the DB keeps the full, uncensored record) ────────
PII_KEYS_WHOLE = {"shipping_address", "billing_address", "default_address", "addresses", "client_details",
                  "browser_ip", "customer_locale", "landing_site", "referring_site", "invoice_url", "note_attributes"}
PII_KEYS = {"email", "phone", "phone_number", "address", "address1", "address2", "zip", "latitude", "longitude",
            "first_name", "last_name", "firstname", "lastname", "company", "contact_email", "customer_email",
            "ip", "cart_token", "checkout_token", "token"}
PERSON_CONTAINERS = {"customer", "requester", "receiver", "sender", "user"}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<![\w/.:-])\+?\d[\d\s().\-]{8,}\d(?![\w/.:-])")
ADDRESS_KEYS = {"address1", "address2", "city", "zip", "first_name", "last_name", "name", "phone", "company"}

def _is_staff(obj):
    meta = obj.get("meta")
    if isinstance(meta, dict) and meta.get("is_staff"): return True
    email = obj.get("email")
    return isinstance(email, str) and email.lower().split("@")[-1] in ALLOWED_DOMAINS

def _collect_pii(obj, parent_key, found):
    """Gather the customer's actual PII values so they can also be scrubbed out of free text
    (message bodies quote names and shipping addresses verbatim)."""
    if isinstance(obj, dict):
        staff = _is_staff(obj)
        for k, v in obj.items():
            kl = str(k).lower()
            if isinstance(v, str) and len(v.strip()) >= 4 and not staff:
                if kl in PII_KEYS and kl not in ("token", "cart_token", "checkout_token"):
                    found.add(v.strip())
                elif kl in ("name", "firstname", "lastname") and parent_key in PERSON_CONTAINERS:
                    found.add(v.strip())
                elif kl in ADDRESS_KEYS and parent_key in PII_KEYS_WHOLE:
                    found.add(v.strip())
            _collect_pii(v, kl, found)
    elif isinstance(obj, list):
        for x in obj: _collect_pii(x, parent_key, found)

def _mask_email(m):
    e = m.group(0)
    return e if e.lower().split("@")[-1] in ALLOWED_DOMAINS else "[email]"

def _censor_str(s, values_rx):
    if values_rx is not None:
        s = values_rx.sub("[redacted]", s)
    return PHONE_RE.sub("[phone]", EMAIL_RE.sub(_mask_email, s))

def _censor(obj, parent_key, values_rx):
    if isinstance(obj, dict):
        staff = _is_staff(obj)
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if kl in PII_KEYS_WHOLE:
                out[k] = "[redacted]"
            elif kl in PII_KEYS and not staff and v not in (None, "", [], {}):
                out[k] = "[redacted]"
            elif kl in ("name", "firstname", "lastname") and parent_key in PERSON_CONTAINERS and not staff and isinstance(v, str):
                out[k] = "[redacted]"
            else:
                out[k] = _censor(v, kl, values_rx)
        return out
    if isinstance(obj, list):
        return [_censor(x, parent_key, values_rx) for x in obj]
    if isinstance(obj, str):
        return _censor_str(obj, values_rx)
    return obj

def censor(obj, extra_values=None):
    """UI-only redaction. Key-based (addresses, contact fields, customer names) plus value-based:
    every PII value found in structured fields is also scrubbed from free text."""
    found = set(extra_values or [])
    _collect_pii(obj, "", found)
    # also match "First Last" split across fields, and each name part on its own
    parts = set()
    for v in found:
        if " " in v and not any(ch.isdigit() for ch in v):
            parts |= {p for p in v.split() if len(p) >= 3}
    vals = sorted({v for v in found | parts if len(v) >= 3}, key=len, reverse=True)
    # whitespace inside a value also matches '+' / %20 so URL-encoded copies (map links) are caught
    pats = [r"(?:\s|\+|%20)+".join(re.escape(w) for w in v.split()) for v in vals]
    values_rx = re.compile("|".join(pats), re.IGNORECASE) if pats else None
    return _censor(obj, "", values_rx)

CF_LABELS = {"9969": "Contact Reason", "5807": "Product", "11375": "Ticket Resolution",
             "11421": "Additional Resolution", "7630": "AI Intent", "7629": "AI Agent Outcome",
             "13131": "Managed sentiment", "18246": "Courier"}

def snapshot_summary(s):
    raw = s["raw"] or {}
    integ = ((raw.get("customer") or {}).get("integrations") or {})
    integ_types = sorted({(v or {}).get("__integration_type__") for v in integ.values() if isinstance(v, dict)} - {None})
    cf = s["custom_fields"] or {}
    iso = lambda d: d.isoformat() if d else None
    return {
        "gorgiasTicketId": s["gorgias_ticket_id"], "status": s["status"], "channel": s["channel"], "via": s["via"],
        "priority": s["priority"], "language": s["language"], "assignee": s["assignee_name"],
        "tags": s["tags"] or [],
        "customFields": [{"id": k, "label": CF_LABELS.get(str(k), "Field " + str(k)), "value": v} for k, v in cf.items()],
        "created": iso(s["created_datetime"]), "opened": iso(s["opened_datetime"]),
        "closed": iso(s["closed_datetime"]), "lastMessage": iso(s["last_message_datetime"]),
        "messageCount": s["message_count"], "eventCount": len(raw.get("events") or []),
        "integrations": integ_types,
        "satisfaction": raw.get("satisfaction_survey"),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  CTF FIELD OPTIONS (v3.2.0) — live from Gorgias, hardcoded fallback
# ══════════════════════════════════════════════════════════════════════════════
# Dropdowns and filters use Gorgias's own custom-field definitions (choices are "L1::L2").
# FALLBACK_FIELD_CHOICES is used only when Gorgias can't be reached. It was copied from the
# live definitions on 2026-10-01; refresh it if Gorgias options change and the fallback matters.
CTF_FIELD_IDS = {"contactReason": 9969, "product": 5807, "resolution": 11375, "addResolution": 11421}
FALLBACK_FIELD_CHOICES = {
    "contactReason": ["Order Status::No Delays","Order Status::Delays, but Not Lost","Order Status::International (No Delays)",
        "Order Status::International (Delays, but Not Lost)","Order Status::Never Shipped","Order Status::Wrong Address",
        "Order Status::Lost in Transit","Order Status::Delivered, Not Received","Order Status::Returned to Sender",
        "Order Issue::Missing Item From Order","Order Issue::FB Wrong Item / Order","Order Issue::CX Wrong Item / Order",
        "Order Issue::Package Damaged / Damaged Upon Arrival","Order Issue::Return Request","Order Issue::Return Follow Through",
        "Update Order:: Add / Remove / Change Item","Update Order:: Change Address","Cancel::Cancel 1st Product Order",
        "Cancel::Subscription Order","Cancel::Subscription (Unaware)","Cancel::Subscription (Aware)","Subscription::Change Frequency",
        "Subscription::Change Product","Subscription::Change Address","Troubleshooting::Will Not Charge","Troubleshooting::Stopped Working",
        "Troubleshooting::Broken Blade / Attachment","Troubleshooting:: Won't turn OFF","Troubleshooting::Never worked (new device)",
        "Other::Promo Request/Issue","Other::Influencer/Job Inquiry","Other::Wholesale","Other::Payment/Charge Issues","Other::Other",
        "Other::Negative Feedback","Other::Positive Feedback","Other::General Product Question","Other::Social General/Tagging",
        "Order Issue::Received Used Product","Order Issue::Received Unsatisfactory Product","Other::System Notification",
        "Other::General Order Question","Other:: Update Account","Subscription::Skip Order","Order Issue::Missing Item From Kit",
        "Other::Multi-Channel Duplicate"],
    "product": ["No Applicable Product","Product::Blade Refills FlexSeries Pro","Product::Blade Refills FlexSeries",
        "Product::Blade Refills FlexSeries Women's","Product::FlexSeries","Product::FlexSeries Pro","Product::FlexSeries Shaving Kit for Women",
        "Product::BeardSeries Trimmer","Accessories::Travel Case","Accessories::Precision Clipper & Guards","Shave Care::Kit",
        "Shave Care::Lubricating Pre-Shave Oil","Shave Care::Soothing Shave Gel","Shave Care::Hydrating Post-Shave Lotion","Scalp Care::Kit",
        "Scalp Care::Detoxifying Bald Head Cleanser","Scalp Care::Purifying Scalp Exfoliating Scrub","Scalp Care::Refreshing Scalp Moisturizer",
        "Scalp Care::Head & Body Wipes","Accessories::Attachment Kit","Accessories::Travel Case & Charging Dock"],
    "resolution": ["NA/No Response","Information Given","Return Prevented:: Partial Refund","Return Prevented:: Successful Troubleshooting",
        "Return Prevented:: Information/Tips Given","Replacement Sent:: Warranty","Replacement Sent:: Shipping Issue",
        "Replacement Sent::Manufacturer Issue","Replacement Sent::Goodwill Replacement","Sub Cancelation Prevented:: Successful Troubleshooting",
        "Sub Cancelation Prevented:: Benefits Explained","Sub Cancelation Prevented:: Changed Refill Frequency","Sub Cancelation Prevented:: Other",
        "Sub Cancelled::No Reason Provided","Sub Cancelled:: Too expensive","Sub Cancelled:: Enough Stock","Sub Cancelled:: Gifted Shaver",
        "Sub Cancelled:: Unsatisfied","Sub Cancelled:: No Longer Need","Return for Refund::Duplicate Order","Cancelled Order",
        "Updated:: Customer Information","Return for Refund::Gifted Shaver","Return for Refund::Quality Complaint",
        "Return for Refund::Accidental Purchase","Return for Refund::Doesn't Provide a Close Shave","Return for Refund::Misleading Advertisement",
        "Return for Refund::Using a Competitor","Return for Refund::Other","Sub Cancelation Prevented:: Partial Refund",
        "Sub Cancelation Prevented:: Upgrade","Return for Refund::One Time Exception","Hid/Removed Social Comment",
        "Sub Cancelled:: Accidental Subscriber","Updated::Subscription","Updated::Order","Return for Refund::Returnless Refund"],
    "addResolution": ["No Additional Resolution","Return Prevented:: Partial Refund","Return Prevented:: Successful Troubleshooting",
        "Return Prevented:: Information/Tips Given","Replacement Sent:: Warranty","Replacement Sent:: Shipping Issue",
        "Replacement Sent::Manufacturer Issue","Sub Cancelation Prevented:: Successful Troubleshooting","Sub Cancelation Prevented:: Upgrade",
        "Sub Cancelation Prevented:: Benefits Explained","Sub Cancelation Prevented:: Changed Refill Frequency",
        "Sub Cancelation Prevented:: Partial Refund","Sub Cancelation Prevented:: Other","Sub Cancelled:: Too expensive",
        "Sub Cancelled:: Enough Stock","Sub Cancelled:: Gifted Shaver","Sub Cancelled:: Unsatisfied","Sub Cancelled:: No Longer Need",
        "Sub Cancelled::Accidental Subscriber","Updated::Customer Information","Cancelled Order","Updated::Subscription","Updated::Order",
        "Other::Internal Note","Return for Refund::Gifted Shaver","Return for Refund::Duplicate Order","Return for Refund::Quality Complaint",
        "Return for Refund::Accidental Purchase","Return for Refund::Doesn't Provide a Close Shave","Return for Refund::Misleading Advertisement",
        "Return for Refund::Using a Competitor","Return for Refund::Other","Return for Refund::One Time Exception",
        "Replacement Sent::Goodwill Replacement"],
}
FIELD_CACHE = {"at": 0.0, "data": None, "error": ""}
FIELD_CACHE_TTL = 3600
FIELD_CACHE_LOCK = threading.Lock()

def split_choice(c):
    """'Update Order:: Change Address' -> ('Update Order', 'Change Address'); 'Cancelled Order' -> ('Cancelled Order', '')."""
    parts = str(c).split("::", 1)
    return parts[0].strip(), (parts[1].strip() if len(parts) > 1 else "")

def get_ctf_field_options(force=False):
    """{source, fetchedAt, error, fields:{key:[choices]}} — live when possible, fallback otherwise. Never raises."""
    with FIELD_CACHE_LOCK:
        fresh = FIELD_CACHE["data"] is not None and (time.time() - FIELD_CACHE["at"]) < FIELD_CACHE_TTL
        if fresh and not force:
            return FIELD_CACHE["data"]
    live, err = {}, ""
    if GORGIAS_USERNAME and GORGIAS_API_KEY:
        try:
            for key, fid in CTF_FIELD_IDS.items():
                d = gorgias_get(f"/custom-fields/{fid}")
                choices = (d.get("definition") or {}).get("input_settings", {}).get("choices") or d.get("choices")
                if not isinstance(choices, list) or not choices:
                    raise RuntimeError(f"field {fid} returned no choices")
                live[key] = [str(c) for c in choices if c is not None and str(c).strip()]
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            live = {}
    else:
        err = "Gorgias not configured"
    if live:
        data = {"source": "live", "fetchedAt": now_iso(), "error": "", "fields": live}
    else:
        prev = FIELD_CACHE["data"]
        if prev and prev.get("source") == "live":      # keep the last good live copy if a refresh fails
            data = dict(prev, error="refresh failed, serving last live copy: " + err)
        else:
            data = {"source": "fallback", "fetchedAt": None, "error": err, "fields": FALLBACK_FIELD_CHOICES}
        print(f"[Fields] live fetch failed ({err}); using {data['source']}")
    with FIELD_CACHE_LOCK:
        FIELD_CACHE.update({"at": time.time(), "data": data, "error": err})
    return data

def cr_options_for_inject():
    """Legacy window.__CR_L1_OPTIONS / __CR_L2_OPTIONS, now derived from the live Contact Reason field."""
    data = FIELD_CACHE["data"] or {"fields": FALLBACK_FIELD_CHOICES}
    l1, l2 = [], {}
    for c in data["fields"].get("contactReason") or []:
        a, b = split_choice(c)
        if a not in l1: l1.append(a)
        if b: l2.setdefault(a, []).append(b)
    return l1, l2

# ══════════════════════════════════════════════════════════════════════════════
#  NOTION (server-side, import + verify only)
# ══════════════════════════════════════════════════════════════════════════════
_notion_lock = threading.Lock()
_notion_last = [0.0]
NOTION_MIN_INTERVAL = 0.34   # ~3 req/s, Notion's documented average

def n_req(method, path, body=None, tries=7):
    if not NOTION_TOKEN:
        raise RuntimeError("NOTION_TOKEN is not set")
    data = json.dumps(body).encode() if body is not None else None
    last = None
    for attempt in range(tries):
        with _notion_lock:
            gap = time.time() - _notion_last[0]
            if gap < NOTION_MIN_INTERVAL:
                time.sleep(NOTION_MIN_INTERVAL - gap)
            _notion_last[0] = time.time()
        req = urllib.request.Request("https://api.notion.com" + path, data=data, method=method, headers={
            "Authorization": f"Bearer {NOTION_TOKEN}", "Notion-Version": "2022-06-28", "Content-Type": "application/json"})
        try:
            resp = urllib.request.urlopen(req, timeout=90)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = e.read()[:300].decode(errors="replace")
            last = f"Notion {e.code}: {detail}"
            if e.code == 429 or e.code >= 500:
                time.sleep(float(e.headers.get("Retry-After") or min(2 ** attempt, 30)))
                continue
            raise RuntimeError(last)
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
            time.sleep(min(2 ** attempt, 30))
    raise RuntimeError(f"Notion request failed after {tries} attempts: {last}")

def n_query_all(db_id, on_progress=None):
    pages, cursor = [], None
    while True:
        body = {"page_size": 100}
        if cursor: body["start_cursor"] = cursor
        d = n_req("POST", f"/v1/databases/{db_id}/query", body)
        pages.extend(d.get("results") or [])
        if on_progress: on_progress(len(pages))
        if not d.get("has_more"): break
        cursor = d.get("next_cursor")
    return pages

# A page object only carries the first 25 items of a title/rich_text property. Anything at or
# over that is re-read through the paginated property-item endpoint so nothing is cut off.
RICH_EXPAND_AT = 25

def n_full_text(page_id, prop_id):
    parts, cursor = [], None
    while True:
        q = "?page_size=100" + (f"&start_cursor={cursor}" if cursor else "")
        d = n_req("GET", f"/v1/pages/{page_id}/properties/{prop_id}{q}")
        if d.get("object") != "list":
            t = d.get("type"); v = d.get(t) or {}
            return v.get("plain_text", "") if isinstance(v, dict) else ""
        for it in d.get("results") or []:
            t = it.get("type"); v = it.get(t) or {}
            if isinstance(v, dict): parts.append(v.get("plain_text", ""))
        if not d.get("has_more"): break
        cursor = d.get("next_cursor")
    return "".join(parts)

def n_prop_value(p):
    t = p.get("type")
    v = p.get(t)
    if t in ("title", "rich_text"): return "".join((x or {}).get("plain_text", "") for x in (v or []))
    if t == "number": return v
    if t == "checkbox": return bool(v)
    if t == "url": return v or ""
    if t in ("select", "status"): return (v or {}).get("name") if v else None
    if t == "multi_select": return [x.get("name") for x in (v or [])]
    if t == "date": return (v or {}).get("start") if v else None
    if t in ("email", "phone_number", "created_time", "last_edited_time"): return v
    if t == "formula":
        v = v or {}; return v.get(v.get("type"))
    if t in ("people", "created_by", "last_edited_by"):
        if isinstance(v, list): return [x.get("name") or x.get("id") for x in v]
        return (v or {}).get("name") or (v or {}).get("id")
    if t == "relation": return [x.get("id") for x in (v or [])]
    if t == "files": return [x.get("name") for x in (v or [])]
    if t == "unique_id":
        v = v or {}; return f"{v.get('prefix') or ''}{v.get('number')}"
    return v

def n_page_record(page):
    """Complete, normalised property map for a page (long text fully expanded)."""
    props, types, expanded = {}, {}, []
    for name, p in (page.get("properties") or {}).items():
        t = p.get("type"); types[name] = t
        if t in ("title", "rich_text") and len(p.get(t) or []) >= RICH_EXPAND_AT:
            props[name] = n_full_text(page["id"], p.get("id"))
            expanded.append(name)
        else:
            props[name] = n_prop_value(p)
    return {"page_id": page["id"], "created_time": page.get("created_time"),
            "last_edited_time": page.get("last_edited_time"), "props": props, "types": types, "expanded": expanded}

# ── Transforms: Notion property map -> DB columns (shared by import AND verify) ──
def p_text(props, name):
    v = props.get(name)
    if v is None: return ""
    if isinstance(v, (list, dict)): return json.dumps(v)
    return str(v)

def p_num(props, name):
    v = props.get(name)
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None

def p_int(props, name):
    v = props.get(name)
    return int(round(v)) if isinstance(v, (int, float)) and not isinstance(v, bool) else None

def p_bool(props, name):
    return props.get(name) is True

def parse_json_field(s, default):
    """Mirror of the client's safeParse(): '' -> default, then JSON, then single->double quote repair."""
    if s is None or s == "": return default, None
    try:
        return json.loads(s), None
    except Exception:
        pass
    try:
        return json.loads(s.replace("'", '"')), "quote-repaired"
    except Exception:
        return default, "unparseable (v2 showed it as empty too)"

def try_parse_json(txt):
    """Mirror of the client's tryParseJSON()."""
    if not txt: return None
    try: return json.loads(txt)
    except Exception: pass
    for rx, grp in ((r"```(?:json)?\s*([\s\S]+?)```", 1), (r"\[[\s\S]{10,}\]", 0), (r"\{[\s\S]{10,}\}", 0)):
        m = re.search(rx, txt)
        if m:
            try: return json.loads(m.group(grp).strip())
            except Exception: pass
    return None

NOTE_PROP = {"ctf": "CTF Notes", "empathy": "Empathy Notes", "fcr": "FCR Notes", "product": "Product Notes",
             "order": "Order Notes", "returns": "Returns Notes", "promo": "Promo Notes", "retention": "Retention Notes"}

def merge_justifications(just_str, notes):
    """Exactly what v2 displayed: compressed JSON {r,i} expanded, then the per-category Notes override."""
    raw, issue = parse_json_field(just_str, {})
    lossy = []
    if issue: lossy.append(f"Justifications JSON {issue}")
    out = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(v, dict):
                e = {kk: vv for kk, vv in v.items() if kk not in ("r", "i")}
                e["reason"] = v.get("reason") or v.get("r") or ""
                e["improve"] = v.get("improve") or v.get("i") or None
                e["sample"] = v.get("sample") or None
                out[k] = e
                if not notes.get(k) and (len(str(v.get("r") or "")) >= 150 or len(str(v.get("i") or "")) >= 100):
                    lossy.append(f"justification '{k}' was cut by v2's 150/100-char JSON cap (no Notes backup)")
    for cat, text in notes.items():
        if text:
            parts = text.split(" | ↑ ")
            e = dict(out.get(cat) or {})
            e["reason"] = parts[0] or ""
            e["improve"] = (parts[1] if len(parts) > 1 else None) or None
            e["sample"] = None
            out[cat] = e
            if len(text) == 1990:
                lossy.append(f"{NOTE_PROP[cat]} hit v2's 1990-char cap")
    return out, lossy

def tf_tickets(rec):
    P = rec["props"]; lossy = []
    def j(name, default):
        val, issue = parse_json_field(p_text(P, name), default)
        if issue: lossy.append(f"{name} {issue}")
        return val
    notes = {cat: p_text(P, prop) for cat, prop in NOTE_PROP.items()}
    just, jl = merge_justifications(p_text(P, "Justifications JSON"), notes)
    lossy += jl
    cols = {
        "ticket_id": p_text(P, "Ticket ID"), "agent_name": p_text(P, "Agent"), "auditor": p_text(P, "Auditor"),
        "week": p_text(P, "Week"), "created_date": p_text(P, "Created Date"), "contact_reason": p_text(P, "Contact Reason"),
        "subject": p_text(P, "Subject"), "ticket_url": p_text(P, "Ticket URL"),
        "ai_score": p_num(P, "AI Score"), "final_score": p_num(P, "Final Score"),
        "ai_passed": p_bool(P, "AI Passed"), "final_passed": p_bool(P, "Final Passed"), "has_disputes": p_bool(P, "Has Disputes"),
        "reviewed": p_bool(P, "Reviewed"), "reviewed_by": p_text(P, "Reviewed By"), "reviewed_at": p_text(P, "Reviewed At"),
        "reviewer_notes": p_text(P, "Reviewer Notes"), "autofail": p_bool(P, "Autofail"), "autofail_manual": p_bool(P, "Autofail Manual"),
        "scores": j("Scores JSON", {}), "disputes": j("Disputes JSON", {}), "justifications": just,
        "autofails": j("Autofails JSON", []), "notes_history": j("Notes History JSON", {}),
        "reopen_history": j("Reopen History JSON", []), "reaudit_history": j("Reaudit History", []),
        "comments": p_text(P, "Comments"), "transcript": p_text(P, "Transcript"), "saved_at": p_text(P, "Saved At"),
        "audit_type": p_text(P, "Audit Type"), "message_count": p_int(P, "Message Count"),
        "agent_message_count": p_int(P, "Agent Message Count"),
        "deleted": p_bool(P, "Deleted"), "deleted_by": p_text(P, "Deleted By"), "deleted_at": p_text(P, "Deleted At"),
        "delete_reason": p_text(P, "Delete Reason"),
        "unlocked_override": p_bool(P, "Unlocked Override"), "unlocked_by": p_text(P, "Unlocked By"),
        "unlocked_at": p_text(P, "Unlocked At"), "unlock_reason": p_text(P, "Unlock Reason"),
    }
    for cat in NOTE_PROP:
        cols[f"{cat}_notes"] = notes[cat]
    if rec["expanded"]:
        lossy.append("info: long text re-read in full via the property endpoint (v2 only saw the first 25 fragments): "
                     + ", ".join(rec["expanded"]))
    return cols, lossy

def tf_users(rec):
    P = rec["props"]
    return {
        "email": p_text(P, "Email").lower().strip(), "name": p_text(P, "Name").strip(),
        "role": (p_text(P, "Role") or "").lower().strip() or "view",
        "active": P.get("Active") is not False, "assign_audits": P.get("Assign Audits") is not False,
        "exclude_tickets": P.get("Exclude Their Tickets") is True, "notes": p_text(P, "Notes").strip(),
    }, []

def tf_reports(rec):
    P = rec["props"]
    lossy = []
    if len(p_text(P, "Report Content 20")) >= 1990:
        lossy.append("report filled all 20 x 1990-char chunks in v2 — its HTML was likely cut at save time")
    return {"agent_email": p_text(P, "Agent Email"), "agent_name": p_text(P, "Agent Name"), "week": p_text(P, "Week"),
            "generated_at": p_text(P, "Generated At"), "generated_by": p_text(P, "Generated By"),
            "content": "".join(p_text(P, f"Report Content {i}") for i in range(1, 21))}, lossy

def tf_calib_rounds(rec):
    P = rec["props"]; lossy = []
    parts = try_parse_json(p_text(P, "Participants") or "[]")
    pool = try_parse_json(p_text(P, "Pool") or "[]")
    if parts is None and p_text(P, "Participants"): lossy.append("Participants unparseable")
    if pool is None and p_text(P, "Pool"): lossy.append("Pool unparseable")
    ins_txt = "".join(p_text(P, f"Insights Content {i}") for i in range(1, 11))
    insights = try_parse_json(ins_txt) if ins_txt else None
    if ins_txt and insights is None: lossy.append("Insights Content unparseable")
    return {"week": p_text(P, "Week"), "status": p_text(P, "Status"),
            "participants": parts if parts is not None else [], "pool": pool if pool is not None else [],
            "created_at_text": p_text(P, "Created At"), "created_by": p_text(P, "Created By"),
            "insights_generated_at": p_text(P, "Insights Generated At"), "insights": insights}, lossy

def tf_calib_reviews(rec):
    P = rec["props"]; lossy = []
    sc = try_parse_json(p_text(P, "Scores") or "{}")
    nt = try_parse_json(p_text(P, "Notes") or "{}")
    if sc is None and p_text(P, "Scores"): lossy.append("Scores unparseable")
    if nt is None and p_text(P, "Notes"): lossy.append("Notes unparseable")
    return {"assignment_id": p_text(P, "Assignment ID"), "week": p_text(P, "Week"), "ticket_id": p_text(P, "Ticket ID"),
            "reviewer_email": p_text(P, "Reviewer Email"), "reviewer_name": p_text(P, "Reviewer Name"),
            "status": p_text(P, "Status"), "scores": sc if sc is not None else {}, "notes": nt if nt is not None else {},
            "autofail": p_bool(P, "Autofail"), "submitted_at": p_text(P, "Submitted At")}, lossy

JSON_COLS = {
    "tickets": {"scores", "disputes", "justifications", "autofails", "notes_history", "reopen_history", "reaudit_history"},
    "qa_users": set(), "reports": set(),
    "calib_rounds": {"participants", "pool", "insights"},
    "calib_reviews": {"scores", "notes"},
}
MAPPED_PROPS = {
    "tickets": {"Ticket ID", "Agent", "Auditor", "Week", "Created Date", "Contact Reason", "Subject", "Ticket URL",
                "AI Score", "Final Score", "AI Passed", "Final Passed", "Has Disputes", "Reviewed", "Reviewed By",
                "Reviewed At", "Reviewer Notes", "Autofail", "Autofail Manual", "Scores JSON", "Disputes JSON",
                "Justifications JSON", "Autofails JSON", "Notes History JSON", "Reopen History JSON", "Reaudit History",
                "Comments", "Transcript", "Saved At", "Audit Type", "Message Count", "Agent Message Count", "Deleted",
                "Deleted By", "Deleted At", "Delete Reason", "Unlocked Override", "Unlocked By", "Unlocked At",
                "Unlock Reason"} | set(NOTE_PROP.values()),
    "qa_users": {"Email", "Name", "Role", "Active", "Assign Audits", "Exclude Their Tickets", "Notes"},
    "reports": {"Agent Email", "Agent Name", "Week", "Generated At", "Generated By"} | {f"Report Content {i}" for i in range(1, 21)},
    "calib_rounds": {"Week", "Status", "Participants", "Pool", "Created At", "Created By", "Insights Generated At"} | {f"Insights Content {i}" for i in range(1, 11)},
    "calib_reviews": {"Assignment ID", "Week", "Ticket ID", "Reviewer Email", "Reviewer Name", "Status", "Scores", "Notes", "Autofail", "Submitted At"},
}
TRANSFORMS = {"tickets": tf_tickets, "qa_users": tf_users, "reports": tf_reports,
              "calib_rounds": tf_calib_rounds, "calib_reviews": tf_calib_reviews}
KEY_LABEL = {"tickets": "ticket_id", "qa_users": "email", "reports": "agent_email",
             "calib_rounds": "week", "calib_reviews": "assignment_id"}
TABLE_ORDER = ["qa_users", "config", "tickets", "reports", "calib_rounds", "calib_reviews"]

# ── Config assembly (Key / Value chunks: key, key__1, key__2, ...) ─────────────
def assemble_config(records):
    groups, dupes = {}, []
    for rec in records:
        key = p_text(rec["props"], "Key")
        m = re.match(r"^(.*)__(\d+)$", key)
        base, idx = (m.group(1), int(m.group(2))) if m else (key, 0)
        g = groups.setdefault(base, {})
        if idx in g:
            dupes.append(key)
            if (rec.get("last_edited_time") or "") <= (g[idx].get("last_edited_time") or ""):
                continue
        g[idx] = rec
    out = {}
    for base, chunks in groups.items():
        info = {"chunksInNotion": sorted(chunks.keys()), "lossy": []}
        if 0 not in chunks:
            info["lossy"].append("orphan chunks with no base key — v2 never read these")
            info["chunksUsed"] = None
            out[base] = (None, info, [])
            continue
        seq = []; i = 0
        while i in chunks:
            seq.append(chunks[i]); i += 1
        vals = [p_text(r["props"], "Value") for r in seq]
        # What v2's loader saw: base + __1..__9 (stops at 10), then JSON.parse
        try:
            json.loads("".join(vals[:10])); info["v2ReadOk"] = bool(vals[0])
        except Exception:
            info["v2ReadOk"] = False
        value, used, acc = None, None, ""
        for k, v in enumerate(vals):
            acc += v
            try:
                value = json.loads(acc); used = k + 1; break
            except Exception:
                continue
        info["chunksUsed"] = used
        info["chunkChars"] = [len(v) for v in vals]
        if used is None:
            info["lossy"].append("value never forms valid JSON — unrecoverable in Notion")
        else:
            if len(vals) > used:
                info["lossy"].append(f"{len(vals) - used} stale chunk(s) after the valid value were ignored")
            if not info["v2ReadOk"]:
                why = (f"needs {used} chunks; v2 stops at 10" if used > 10
                       else "v2 also appended the stale chunk(s), so its JSON.parse failed")
                info["lossy"].append(f"v2 could NOT read this key ({why}) — the app was silently using its defaults")
        if max(chunks.keys()) >= len(seq):
            info["lossy"].append("chunks exist after a gap in the sequence (ignored)")
        out[base] = (value if used is not None else None, info, seq)
    return out, dupes

def strict_equal(a, b):
    """Deep equality that does NOT treat True == 1, and compares numbers by value (85 == 85.0)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(float(a) - float(b)) < 1e-9
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(strict_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(strict_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b

# ══════════════════════════════════════════════════════════════════════════════
#  BACKGROUND JOBS (import / verify)
# ══════════════════════════════════════════════════════════════════════════════
JOBS = {"import": None, "verify": None}
JOBS_LOCK = threading.Lock()

def job_new(kind, by):
    return {"kind": kind, "by": by, "running": True, "startedAt": now_iso(), "finishedAt": None,
            "phase": "starting", "progress": {}, "log": [], "error": None, "result": None, "runId": None}

def job_log(job, msg):
    print(f"[{job['kind'].title()}] {msg}")
    job["log"].append(f"{datetime.now(timezone.utc).strftime('%H:%M:%S')} {msg}")
    if len(job["log"]) > 400:
        job["log"] = job["log"][-400:]

def fetch_notion_table(job, table):
    job["phase"] = f"reading {table} from Notion"
    def prog(n): job["progress"][table] = {"fetched": n}
    pages = n_query_all(NOTION_DBS[table], prog)
    recs = []
    for i, p in enumerate(pages):
        recs.append(n_page_record(p))
        if (i + 1) % 250 == 0:
            job_log(job, f"{table}: normalised {i + 1}/{len(pages)} pages")
    expanded = sum(1 for r in recs if r["expanded"])
    job_log(job, f"{table}: {len(recs)} pages read" + (f" ({expanded} with long text re-read in full)" if expanded else ""))
    return recs

def _adapt(table, col, v):
    return Jsonb(v) if (col in JSON_COLS.get(table, set()) and v is not None) else v

def import_table(job, conn, table, recs):
    tf = TRANSFORMS[table]
    written, skipped, lossy_rows = 0, [], 0
    seen_emails = {}
    for rec in recs:
        cols, lossy = tf(rec)
        if [l for l in lossy if not l.startswith("info:")]: lossy_rows += 1
        if table == "qa_users":
            if not cols["email"]:
                skipped.append({"pageId": rec["page_id"], "why": "no email"}); continue
            if cols["email"] in seen_emails:
                skipped.append({"pageId": rec["page_id"], "why": f"duplicate email {cols['email']} (kept {seen_emails[cols['email']]})"}); continue
            seen_emails[cols["email"]] = rec["page_id"]
        names = list(cols.keys())
        values = [_adapt(table, c, cols[c]) for c in names]
        conflict = "email" if table == "qa_users" else "notion_page_id"
        set_clause = ", ".join(f"{c}=EXCLUDED.{c}" for c in names + ["notion_page_id", "notion_raw"])
        sql = (f"INSERT INTO {table} (id, {', '.join(names)}, notion_page_id, notion_raw, imported_at, updated_at, app_updated_at) "
               f"VALUES (%s, {', '.join(['%s'] * len(names))}, %s, %s, now(), now(), NULL) "
               f"ON CONFLICT ({conflict}) DO UPDATE SET {set_clause}, archived=false, imported_at=now(), updated_at=now(), app_updated_at=NULL"
               if table == "qa_users" else
               f"INSERT INTO {table} (id, {', '.join(names)}, notion_page_id, notion_raw, imported_at, updated_at, app_updated_at) "
               f"VALUES (%s, {', '.join(['%s'] * len(names))}, %s, %s, now(), now(), NULL) "
               f"ON CONFLICT ({conflict}) DO UPDATE SET {set_clause}, imported_at=now(), updated_at=now(), app_updated_at=NULL")
        conn.execute(sql, [rec["page_id"]] + values + [rec["page_id"], Jsonb(rec)])
        written += 1
        if written % 250 == 0:
            job["progress"][table] = {"fetched": len(recs), "written": written}
    job["progress"][table] = {"fetched": len(recs), "written": written, "skipped": len(skipped)}
    job_log(job, f"{table}: {written} rows written, {len(skipped)} skipped, {lossy_rows} with source-side issues")
    return {"notion": len(recs), "written": written, "skipped": skipped, "rowsWithSourceIssues": lossy_rows}

def import_config(job, conn, recs, by):
    assembled, dupes = assemble_config(recs)
    summary = {"notion": len(recs), "keys": {}, "duplicateKeys": dupes}
    for key, (value, info, seq) in assembled.items():
        if info.get("chunksUsed") is None:
            summary["keys"][key] = info
            job_log(job, f"config '{key}': NOT imported — {'; '.join(info['lossy'])}")
            continue
        raw = {"chunks": [{"page_id": r["page_id"], "key": p_text(r["props"], "Key"),
                           "value": p_text(r["props"], "Value"), "last_edited_time": r.get("last_edited_time")} for r in seq],
               "info": info}
        cur = conn.execute("SELECT value, version FROM config WHERE key=%s FOR UPDATE", (key,)).fetchone()
        if cur is None:
            ver = 1
            conn.execute("INSERT INTO config (key, value, version, updated_by, updated_at, notion_raw) VALUES (%s,%s,1,%s,now(),%s)",
                         (key, Jsonb(value), f"import ({by})", Jsonb(raw)))
            conn.execute("INSERT INTO config_history (key, version, value, saved_by, source) VALUES (%s,1,%s,%s,'import')",
                         (key, Jsonb(value), f"import ({by})"))
        elif strict_equal(cur["value"], value):
            ver = cur["version"]
            conn.execute("UPDATE config SET notion_raw=%s WHERE key=%s", (Jsonb(raw), key))
            if not conn.execute("SELECT 1 FROM config_history WHERE key=%s AND source='import'", (key,)).fetchone():
                conn.execute("UPDATE config_history SET source='import' WHERE key=%s AND version=%s", (key, ver))
        else:
            ver = cur["version"] + 1
            conn.execute("UPDATE config SET value=%s, version=%s, updated_by=%s, updated_at=now(), notion_raw=%s WHERE key=%s",
                         (Jsonb(value), ver, f"import ({by})", Jsonb(raw), key))
            conn.execute("INSERT INTO config_history (key, version, value, saved_by, source) VALUES (%s,%s,%s,%s,'import')",
                         (key, ver, Jsonb(value), f"import ({by})"))
        info["version"] = ver
        info["chars"] = len(json.dumps(value))
        summary["keys"][key] = info
        job_log(job, f"config '{key}': imported as v{ver} ({info['chars']} chars from {info['chunksUsed']} chunk(s))"
                     + (f" — {'; '.join(info['lossy'])}" if info["lossy"] else ""))
    return summary

def run_import(job, by):
    run_id = None
    try:
        run_id = db_one("INSERT INTO admin_runs (kind, started_by) VALUES ('import', %s) RETURNING id", (by,))["id"]
        job["runId"] = run_id
        results = {}
        for table in TABLE_ORDER:
            recs = fetch_notion_table(job, table)
            job["phase"] = f"writing {table}"
            with POOL.connection() as conn:   # one transaction per table
                results[table] = import_config(job, conn, recs, by) if table == "config" else import_table(job, conn, table, recs)
            job["result"] = results
        job["phase"] = "done"
        db_exec("UPDATE admin_runs SET finished_at=now(), status='done', summary=%s WHERE id=%s", (Jsonb(results), run_id))
        job_log(job, "Import complete. Run Verify next.")
    except Exception as e:
        job["error"] = f"{type(e).__name__}: {e}"
        job["phase"] = "failed"
        job_log(job, "FAILED: " + job["error"])
        traceback.print_exc()
        if run_id:
            db_exec("UPDATE admin_runs SET finished_at=now(), status='failed', summary=%s WHERE id=%s",
                    (Jsonb({"error": job["error"], "partial": job.get("result")}), run_id))
    finally:
        job["running"] = False
        job["finishedAt"] = now_iso()

# ── Verify ─────────────────────────────────────────────────────────────────────
def preview(v):
    s = v if isinstance(v, str) else json.dumps(v, default=str)
    return {"len": len(s), "sha1": hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()[:12],
            "head": s[:300], "tail": s[-120:] if len(s) > 420 else ""}

MAX_DETAIL = 5000

def verify_table(job, table, recs, detail):
    tf = TRANSFORMS[table]
    rows = db_all(f"SELECT * FROM {table} WHERE notion_page_id IS NOT NULL")
    by_pid = {r["notion_page_id"]: r for r in rows}
    app_created = db_one(f"SELECT count(*) AS n FROM {table} WHERE notion_page_id IS NULL")["n"]
    res = {"notion": len(recs), "dbImported": len(rows), "dbAppCreated": app_created, "missingInDb": 0,
           "extraInDb": 0, "expectedSkips": 0, "fieldMismatches": 0, "rowsWithMismatch": 0, "rawMismatches": 0,
           "modifiedInWingman": 0, "rowsWithSourceIssues": 0, "unmappedProps": []}
    live_pids, seen_emails, all_props = set(), {}, set()
    for rec in recs:
        pid = rec["page_id"]; live_pids.add(pid)
        all_props |= set(rec["props"].keys())
        cols, lossy = tf(rec)
        key = cols.get(KEY_LABEL[table], "")
        if table == "qa_users":
            if not cols["email"] or cols["email"] in seen_emails:
                res["expectedSkips"] += 1; continue
            seen_emails[cols["email"]] = pid
        real_lossy = [l for l in lossy if not l.startswith("info:")]
        if real_lossy:
            res["rowsWithSourceIssues"] += 1
            if len(detail["lossy"]) < MAX_DETAIL:
                detail["lossy"].append({"table": table, "notionPageId": pid, "key": key, "issues": real_lossy})
        for l in lossy:
            if l.startswith("info:") and len(detail["info"]) < MAX_DETAIL:
                detail["info"].append({"table": table, "notionPageId": pid, "key": key, "note": l[5:].strip()})
        row = by_pid.get(pid)
        if row is None:
            res["missingInDb"] += 1
            if len(detail["missing"]) < MAX_DETAIL:
                detail["missing"].append({"table": table, "notionPageId": pid, "key": key})
            continue
        # Check 1: Notion now vs Notion as captured at import (capture was lossless, nothing changed since)
        saved_props = ((row.get("notion_raw") or {}).get("props") or {})
        raw_bad = [n for n in set(rec["props"]) | set(saved_props) if not strict_equal(rec["props"].get(n), saved_props.get(n))]
        if raw_bad:
            res["rawMismatches"] += 1
            if len(detail["raw"]) < MAX_DETAIL:
                detail["raw"].append({"table": table, "notionPageId": pid, "key": key, "props": sorted(raw_bad)})
        # Check 2: Notion -> typed columns, field by field (skipped once Wingman itself edited the row)
        if row.get("app_updated_at"):
            res["modifiedInWingman"] += 1
            continue
        bad = False
        for col, expected in cols.items():
            actual = row.get(col)
            if not strict_equal(expected, actual):
                res["fieldMismatches"] += 1; bad = True
                if len(detail["mismatches"]) < MAX_DETAIL:
                    detail["mismatches"].append({"table": table, "notionPageId": pid, "key": key, "field": col,
                                                 "notion": preview(expected), "db": preview(actual)})
        if bad: res["rowsWithMismatch"] += 1
    for pid, r in by_pid.items():
        if pid not in live_pids:
            res["extraInDb"] += 1
            if len(detail["extra"]) < MAX_DETAIL:
                detail["extra"].append({"table": table, "notionPageId": pid, "key": r.get(KEY_LABEL[table], "")})
    res["unmappedProps"] = sorted(all_props - MAPPED_PROPS[table])
    res["passed"] = (res["missingInDb"] == 0 and res["extraInDb"] == 0 and res["fieldMismatches"] == 0
                     and res["rawMismatches"] == 0 and (len(recs) - res["expectedSkips"]) == len(rows))
    return res

def verify_config(job, recs, detail):
    assembled, dupes = assemble_config(recs)
    res = {"notion": len(recs), "keys": {}, "duplicateKeys": dupes, "fieldMismatches": 0, "missingInDb": 0}
    for key, (value, info, seq) in assembled.items():
        k = {"lossy": info["lossy"], "v2ReadOk": info.get("v2ReadOk"), "chunksUsed": info.get("chunksUsed")}
        if info["lossy"] and len(detail["lossy"]) < MAX_DETAIL:
            detail["lossy"].append({"table": "config", "key": key, "issues": info["lossy"]})
        if info.get("chunksUsed") is None:
            k["status"] = "unrecoverable in Notion (reported, not a failure)"; res["keys"][key] = k; continue
        h = db_one("SELECT value, version FROM config_history WHERE key=%s AND source='import' ORDER BY version DESC LIMIT 1", (key,))
        if h is None:
            res["missingInDb"] += 1; k["status"] = "missing in DB"
            detail["missing"].append({"table": "config", "key": key})
        elif strict_equal(h["value"], value):
            k["status"] = "match"; k["version"] = h["version"]
        else:
            res["fieldMismatches"] += 1; k["status"] = "MISMATCH"
            detail["mismatches"].append({"table": "config", "key": key, "field": "value",
                                         "notion": preview(value), "db": preview(h["value"])})
        cur = db_one("SELECT version FROM config WHERE key=%s", (key,))
        if cur and h and cur["version"] != h["version"]:
            k["changedInWingmanSince"] = f"v{h['version']} -> v{cur['version']}"
        res["keys"][key] = k
    res["passed"] = res["fieldMismatches"] == 0 and res["missingInDb"] == 0
    return res

def run_verify(job, by):
    run_id = None
    try:
        run_id = db_one("INSERT INTO admin_runs (kind, started_by) VALUES ('verify', %s) RETURNING id", (by,))["id"]
        job["runId"] = run_id
        detail = {"missing": [], "extra": [], "mismatches": [], "raw": [], "lossy": [], "info": []}
        tables = {}
        for table in TABLE_ORDER:
            recs = fetch_notion_table(job, table)
            job["phase"] = f"comparing {table}"
            tables[table] = verify_config(job, recs, detail) if table == "config" else verify_table(job, table, recs, detail)
            t = tables[table]
            job_log(job, f"{table}: {'PASS' if t['passed'] else 'FAIL'} " +
                    json.dumps({k: v for k, v in t.items() if k not in ("keys", "unmappedProps", "passed", "duplicateKeys")}))
            if t.get("unmappedProps"):
                job_log(job, f"{table}: Notion properties with no DB column (still preserved in notion_raw): {', '.join(t['unmappedProps'])}")
        passed = all(t["passed"] for t in tables.values())
        summary = {"passed": passed, "tables": tables, "counts": {k: len(v) for k, v in detail.items()}, "verifiedAt": now_iso()}
        job["result"] = summary
        job["phase"] = "done"
        db_exec("UPDATE admin_runs SET finished_at=now(), status='done', passed=%s, summary=%s, detail=%s WHERE id=%s",
                (passed, Jsonb(summary), Jsonb(detail), run_id))
        job_log(job, "VERIFY " + ("PASSED — 100% of Notion data is in Postgres" if passed else "FAILED — download the report for details"))
    except Exception as e:
        job["error"] = f"{type(e).__name__}: {e}"
        job["phase"] = "failed"
        job_log(job, "FAILED: " + job["error"])
        traceback.print_exc()
        if run_id:
            db_exec("UPDATE admin_runs SET finished_at=now(), status='failed', passed=false, summary=%s WHERE id=%s",
                    (Jsonb({"error": job["error"]}), run_id))
    finally:
        job["running"] = False
        job["finishedAt"] = now_iso()

def start_job(kind, by):
    with JOBS_LOCK:
        for k, j in JOBS.items():
            if j and j["running"]:
                raise ApiError(409, f"{k} is already running — wait for it to finish")
        job = job_new(kind, by)
        JOBS[kind] = job
    threading.Thread(target=run_import if kind == "import" else run_verify, args=(job, by), daemon=True).start()
    return job

def last_run(kind):
    r = db_one("SELECT id, started_by, started_at, finished_at, status, passed, summary FROM admin_runs WHERE kind=%s ORDER BY id DESC LIMIT 1", (kind,))
    if not r: return None
    return {"id": r["id"], "startedBy": r["started_by"], "startedAt": r["started_at"].isoformat() if r["started_at"] else None,
            "finishedAt": r["finished_at"].isoformat() if r["finished_at"] else None, "status": r["status"],
            "passed": r["passed"], "summary": r["summary"]}

# ══════════════════════════════════════════════════════════════════════════════
#  API ENDPOINTS   fn(handler, user, path_params, query, body) -> json
# ══════════════════════════════════════════════════════════════════════════════

# ── Me / users ────────────────────────────────────────────────────────────────
# ── Autofail dispute window (v3.7.0) ────────────────────────────────────────────
# While open, agents may file — and auditors decide — AUTOFAIL disputes on audits that are otherwise locked
# (the Wednesday lock). Category scores/disputes stay locked. Closes itself after `until` (Manila date).
def manila_today():
    return (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%d")

def autofail_window_state():
    w = state_get("autofail_dispute_window") or {}
    active = bool(w.get("open")) and bool(w.get("until")) and manila_today() <= w["until"]
    return {"open": bool(w.get("open")), "active": active, "until": w.get("until", ""), "from": w.get("from", ""),
            "to": w.get("to", ""), "openedBy": w.get("openedBy", ""), "openedAt": w.get("openedAt", ""),
            "history": (w.get("history") or [])[-20:], "today": manila_today()}

def api_autofail_window_get(h, user, pp, qs, body):
    return autofail_window_state()

def api_autofail_window_put(h, user, pp, qs, body):
    w = state_get("autofail_dispute_window") or {}
    want_open = bool(body.get("open"))
    until = c_text(body.get("until")).strip()[:10]
    frm, to = c_text(body.get("from")).strip()[:10], c_text(body.get("to")).strip()[:10]
    date_rx = r"\d{4}-\d{2}-\d{2}"
    if want_open:
        if not re.fullmatch(date_rx, until): raise ApiError(400, "until must be a date (YYYY-MM-DD)")
        if until < manila_today(): raise ApiError(400, "the end date is in the past")
    for d in (frm, to):
        if d and not re.fullmatch(date_rx, d): raise ApiError(400, "audit range dates must be YYYY-MM-DD")
    if frm and to and frm > to: raise ApiError(400, "audit range: 'from' is after 'to'")
    hist = (w.get("history") or [])
    hist.append({"action": ("open" if want_open and not w.get("open") else "update" if want_open else "close"),
                 "by": user["name"], "at": now_iso(), "until": until if want_open else "", "from": frm, "to": to})
    new = dict(w, open=want_open, until=until if want_open else w.get("until", ""), history=hist[-50:])
    if want_open:
        new.update({"from": frm, "to": to})
        if not w.get("open"): new.update({"openedBy": user["name"], "openedAt": now_iso()})
    state_set("autofail_dispute_window", new)
    return autofail_window_state()

def api_me(h, user, pp, qs, body):
    c = cutover_state()
    return dict(user, ok=True, cutover=c, migrationMode=not c.get("done"), autofailWindow=autofail_window_state())

def api_users_list(h, user, pp, qs, body):
    if user.get("bootstrap") or role_rank(user["role"]) < 1:
        return {"users": [user]}   # bootstrap, or view/agent: themselves only
    rows = db_all("SELECT * FROM qa_users WHERE NOT archived ORDER BY created_at, email")
    return {"users": [user_row_to_api(r) for r in rows]}

USER_FIELDS = {"name": ("name", "text"), "role": ("role", "text"), "active": ("active", "bool"),
               "assignAudits": ("assign_audits", "bool"), "excludeTickets": ("exclude_tickets", "bool"),
               "notes": ("notes", "text")}
VALID_ROLES = {"full", "edit", "view", "agent"}

def _user_cols(body):
    cols = {}
    for k, (col, kind) in USER_FIELDS.items():
        if k in body:
            cols[col] = coerce(kind, body[k])
    if "role" in cols:
        cols["role"] = cols["role"].lower().strip()
        if cols["role"] not in VALID_ROLES: raise ApiError(400, "invalid role")
    return cols

def api_users_create(h, user, pp, qs, body):
    em = (body.get("email") or "").lower().strip()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", em): raise ApiError(400, "valid email required")
    cols = _user_cols(body)
    cols.setdefault("name", em.split("@")[0]); cols.setdefault("role", "edit"); cols.setdefault("active", True)
    existing = db_one("SELECT id, archived FROM qa_users WHERE lower(email)=%s", (em,))
    if existing and not existing["archived"]:
        raise ApiError(409, "User already exists")
    if existing:   # re-adding a removed user
        sets = ", ".join(f"{c}=%s" for c in cols)
        db_exec(f"UPDATE qa_users SET {sets}, archived=false, updated_at=now(), app_updated_at=now() WHERE id=%s",
                list(cols.values()) + [existing["id"]])
        return {"id": str(existing["id"])}
    names = ["email"] + list(cols.keys())
    r = db_one(f"INSERT INTO qa_users ({', '.join(names)}, app_updated_at) VALUES ({', '.join(['%s'] * len(names))}, now()) RETURNING id",
               [em] + list(cols.values()))
    return {"id": str(r["id"])}

def api_users_update(h, user, pp, qs, body):
    if not is_uuid(pp["id"]): raise ApiError(404, "user not found")
    cols = _user_cols(body)
    if not cols: return {"ok": True}
    sets = ", ".join(f"{c}=%s" for c in cols)
    n = db_exec(f"UPDATE qa_users SET {sets}, updated_at=now(), app_updated_at=now() WHERE id=%s AND NOT archived",
                list(cols.values()) + [pp["id"]])
    if not n: raise ApiError(404, "user not found")
    return {"ok": True}

def api_users_delete(h, user, pp, qs, body):
    if not is_uuid(pp["id"]): raise ApiError(404, "user not found")
    n = db_exec("UPDATE qa_users SET archived=true, updated_at=now(), app_updated_at=now() WHERE id=%s", (pp["id"],))
    if not n: raise ApiError(404, "user not found")
    return {"ok": True}

# ── Tickets ───────────────────────────────────────────────────────────────────
def _agent_scope(user):
    """view/agent users only ever see their own audits (v2 filtered this client-side only)."""
    if role_rank(user["role"]) >= 1: return None
    return normalize_agent_name(user.get("agentName") or user.get("name") or "")

AGENT_SQL = "btrim(regexp_replace(replace(agent_name, chr(160), ' '), '\\s+', ' ', 'g'))"

def api_tickets_list(h, user, pp, qs, body):
    limit = max(1, min(int(qs.get("limit", "500")), 2000))
    offset = max(0, int(qs.get("offset", "0")))
    where, params = ["NOT deleted"], []
    scope = _agent_scope(user)
    if scope is not None:
        where.append(f"{AGENT_SQL} = %s"); params.append(scope)
    w = " AND ".join(where)
    total = db_one(f"SELECT count(*) AS n FROM tickets WHERE {w}", params)["n"]
    rows = db_all(f"SELECT {TICKET_LIST_COLS} FROM tickets WHERE {w} ORDER BY saved_at DESC, id LIMIT %s OFFSET %s",
                  params + [limit, offset])
    nxt = offset + len(rows)
    return {"rows": [ticket_row_to_api(r) for r in rows], "total": total, "next": nxt if nxt < total else None}

def api_tickets_deleted_ids(h, user, pp, qs, body):
    if _agent_scope(user) is not None: return {"ids": []}
    rows = db_all("SELECT DISTINCT ticket_id FROM tickets WHERE deleted AND ticket_id <> ''")
    return {"ids": [r["ticket_id"] for r in rows]}

def _ticket_or_404(tid, scope=None):
    if not is_uuid(tid): raise ApiError(404, "ticket not found")
    r = db_one(f"SELECT {TICKET_LIST_COLS} FROM tickets WHERE id=%s", (tid,))
    if not r: raise ApiError(404, "ticket not found")
    if scope is not None and normalize_agent_name(r["agent_name"]) != scope:
        raise ApiError(403, "not your ticket")
    return r

def api_ticket_get(h, user, pp, qs, body):
    return ticket_row_to_api(_ticket_or_404(pp["id"], _agent_scope(user)))

def api_ticket_create(h, user, pp, qs, body):
    cols = ticket_payload_to_cols(body)
    if not cols.get("ticket_id"): raise ApiError(400, "ticketId required")
    if cols.get("matrix_version") is None:
        cv = db_one("SELECT version FROM config WHERE key='matrix'")
        if cv: cols["matrix_version"] = cv["version"]
    cols["snapshot_status"] = "pending" if cols["ticket_id"].strip().isdigit() else "skipped"
    names = list(cols.keys())
    r = db_one(f"INSERT INTO tickets ({', '.join(names)}, app_updated_at) VALUES ({', '.join(['%s'] * len(names))}, now()) RETURNING id",
               list(cols.values()))
    if cols["snapshot_status"] == "pending":
        enqueue_snapshot(r["id"])
    return {"id": str(r["id"])}

def _check_agent_disputes(existing, incoming):
    """v3.6.0: agents may only ADD new disputes, and only as pending. Existing disputes (including decided ones) are
    read-only to them, so an agent can't approve their own dispute or rewrite an auditor's decision."""
    if not isinstance(incoming, dict): raise ApiError(400, "disputes must be an object")
    existing = existing or {}
    for k, v in existing.items():
        if k not in incoming or not strict_equal(incoming[k], v):
            raise ApiError(403, "existing disputes can't be changed")
    for k, v in incoming.items():
        if k in existing: continue
        if not isinstance(v, dict) or (v.get("status") or "pending") != "pending" or v.get("decidedBy"):
            raise ApiError(403, "new disputes must be pending")

def api_ticket_patch(h, user, pp, qs, body):
    scope = _agent_scope(user)
    row = _ticket_or_404(pp["id"], scope)
    if scope is not None and "disputes" in body:
        _check_agent_disputes(row["disputes"], c_json(body["disputes"], {}))
    cols = ticket_payload_to_cols(body, allowed=AGENT_WRITABLE if scope is not None else None)
    if not cols: return {"ok": True}
    sets = ", ".join(f"{c}=%s" for c in cols)
    db_exec(f"UPDATE tickets SET {sets}, updated_at=now(), app_updated_at=now() WHERE id=%s", list(cols.values()) + [pp["id"]])
    return {"ok": True}

def api_ticket_snapshot(h, user, pp, qs, body):
    t = _ticket_or_404(pp["id"])
    meta = db_one("SELECT snapshot_status, snapshot_error, snapshot_attempts FROM tickets WHERE id=%s", (pp["id"],))
    out = {"status": meta["snapshot_status"], "error": meta["snapshot_error"], "attempts": meta["snapshot_attempts"],
           "ctfAsScored": t["ctf_as_scored"], "aiMeta": t["ai_meta"], "matrixVersion": t["matrix_version"]}
    s = db_one("SELECT * FROM ticket_snapshots WHERE audit_id=%s ORDER BY fetched_at DESC LIMIT 1", (pp["id"],))
    if s:
        out["fetchedAt"] = s["fetched_at"].isoformat()
        pii = set(); _collect_pii(s["raw"], "", pii)
        out["summary"] = censor(snapshot_summary(s), pii)
        out["raw"] = censor(s["raw"]) if qs.get("raw") == "1" else None
    return out

# ── Config (versioned) ────────────────────────────────────────────────────────
def api_config_get(h, user, pp, qs, body):
    r = db_one("SELECT value, version, updated_by, updated_at FROM config WHERE key=%s", (pp["key"],))
    if not r: return {"key": pp["key"], "exists": False, "value": None, "version": None}
    return {"key": pp["key"], "exists": True, "value": r["value"], "version": r["version"],
            "updatedBy": r["updated_by"], "updatedAt": r["updated_at"].isoformat()}

def api_config_put(h, user, pp, qs, body):
    if "value" not in body: raise ApiError(400, "value required")
    key, value = pp["key"], body["value"]
    with POOL.connection() as conn:
        cur = conn.execute("SELECT value, version FROM config WHERE key=%s FOR UPDATE", (key,)).fetchone()
        if cur and strict_equal(cur["value"], value):
            return {"key": key, "version": cur["version"], "changed": False}
        ver = (cur["version"] + 1) if cur else 1
        if cur:
            conn.execute("UPDATE config SET value=%s, version=%s, updated_by=%s, updated_at=now() WHERE key=%s",
                         (Jsonb(value), ver, user["name"], key))
        else:
            conn.execute("INSERT INTO config (key, value, version, updated_by) VALUES (%s,%s,%s,%s)",
                         (key, Jsonb(value), ver, user["name"]))
        conn.execute("INSERT INTO config_history (key, version, value, saved_by, source) VALUES (%s,%s,%s,%s,'app')",
                     (key, ver, Jsonb(value), user["name"]))
    return {"key": key, "version": ver, "changed": True}

def api_config_history(h, user, pp, qs, body):
    rows = db_all("""SELECT version, saved_by, saved_at, source, length(value::text) AS chars
                     FROM config_history WHERE key=%s ORDER BY version DESC""", (pp["key"],))
    return {"key": pp["key"], "versions": [{"version": r["version"], "savedBy": r["saved_by"], "savedAt": r["saved_at"].isoformat(),
                                             "source": r["source"], "chars": r["chars"]} for r in rows]}

# ── Reports ───────────────────────────────────────────────────────────────────
def _report_api(r):
    return {"id": str(r["id"]), "agentName": r["agent_name"], "agentEmail": r["agent_email"], "week": r["week"],
            "generatedAt": r["generated_at"], "generatedBy": r["generated_by"], "html": r["content"]}

def api_reports_list(h, user, pp, qs, body):
    email = (qs.get("email") or "").lower().strip()
    if role_rank(user["role"]) < 1:
        email = user["email"]          # agents only ever get their own reports
    if email:
        rows = db_all("SELECT * FROM reports WHERE lower(agent_email)=%s ORDER BY generated_at DESC", (email,))
    else:
        rows = db_all("SELECT * FROM reports ORDER BY generated_at DESC")
    return {"reports": [_report_api(r) for r in rows]}

def api_reports_put(h, user, pp, qs, body):
    em = (body.get("agentEmail") or "").strip()
    week = body.get("week") or ""
    html = body.get("html") or ""
    if not em or not html: raise ApiError(400, "agentEmail and html required")
    now = now_iso()
    ex = db_one("SELECT id FROM reports WHERE lower(agent_email)=lower(%s) AND week=%s ORDER BY created_at LIMIT 1", (em, week))
    if ex:
        db_exec("UPDATE reports SET generated_at=%s, generated_by=%s, content=%s, updated_at=now(), app_updated_at=now() WHERE id=%s",
                (now, user["name"], html, ex["id"]))
        return {"id": str(ex["id"]), "updated": True}
    r = db_one("""INSERT INTO reports (agent_email, agent_name, week, generated_at, generated_by, content, app_updated_at)
                  VALUES (%s,%s,%s,%s,%s,%s,now()) RETURNING id""", (em, body.get("agentName") or "", week, now, user["name"], html))
    return {"id": str(r["id"]), "updated": False}

# ── Team Calibration ──────────────────────────────────────────────────────────
ROUND_FIELDS = {"week": ("week", "text"), "status": ("status", "text"), "participants": ("participants", "jarr"),
                "pool": ("pool", "jarr"), "createdAt": ("created_at_text", "text"), "createdBy": ("created_by", "text"),
                "insightsGeneratedAt": ("insights_generated_at", "text"), "insights": ("insights", "json")}
REVIEW_FIELDS = {"assignmentId": ("assignment_id", "text"), "week": ("week", "text"), "ticketId": ("ticket_id", "text"),
                 "reviewerEmail": ("reviewer_email", "text"), "reviewerName": ("reviewer_name", "text"),
                 "status": ("status", "text"), "scores": ("scores", "jobj"), "notes": ("notes", "jobj"),
                 "autofail": ("autofail", "bool"), "submittedAt": ("submitted_at", "text")}

def _cols(fields, body):
    return {col: coerce(kind, body[k]) for k, (col, kind) in fields.items() if k in body}

def _round_api(r, with_insights=False):
    out = {"id": str(r["id"]), "pageId": str(r["id"]), "week": r["week"], "status": r["status"],
           "participants": r["participants"] or [], "pool": r["pool"] or [], "createdAt": r["created_at_text"],
           "createdBy": r["created_by"], "insightsGeneratedAt": r["insights_generated_at"]}
    if with_insights: out["insights"] = r["insights"]
    return out

def api_rounds_list(h, user, pp, qs, body):
    rows = db_all("""SELECT id, week, status, participants, pool, created_at_text, created_by, insights_generated_at
                     FROM calib_rounds ORDER BY created_at_text DESC""")
    return {"rounds": [_round_api(r) for r in rows]}

def api_round_get(h, user, pp, qs, body):
    if not is_uuid(pp["id"]): raise ApiError(404, "round not found")
    r = db_one("SELECT * FROM calib_rounds WHERE id=%s", (pp["id"],))
    if not r: raise ApiError(404, "round not found")
    return _round_api(r, True)

def api_round_create(h, user, pp, qs, body):
    cols = _cols(ROUND_FIELDS, body)
    if not cols.get("week"): raise ApiError(400, "week required")
    names = list(cols.keys())
    r = db_one(f"INSERT INTO calib_rounds ({', '.join(names)}, app_updated_at) VALUES ({', '.join(['%s'] * len(names))}, now()) RETURNING id",
               list(cols.values()))
    return {"id": str(r["id"])}

def api_round_patch(h, user, pp, qs, body):
    if not is_uuid(pp["id"]): raise ApiError(404, "round not found")
    cols = _cols(ROUND_FIELDS, body)
    if not cols: return {"ok": True}
    sets = ", ".join(f"{c}=%s" for c in cols)
    n = db_exec(f"UPDATE calib_rounds SET {sets}, updated_at=now(), app_updated_at=now() WHERE id=%s", list(cols.values()) + [pp["id"]])
    if not n: raise ApiError(404, "round not found")
    return {"ok": True}

def _review_api(r):
    return {"id": str(r["id"]), "pageId": str(r["id"]), "assignmentId": r["assignment_id"], "week": r["week"],
            "ticketId": r["ticket_id"], "reviewerEmail": r["reviewer_email"], "reviewerName": r["reviewer_name"],
            "status": r["status"], "scores": r["scores"] or {}, "notes": r["notes"] or {}, "autofail": r["autofail"],
            "submittedAt": r["submitted_at"]}

def api_reviews_list(h, user, pp, qs, body):
    where, params = [], []
    if "week" in qs: where.append("week=%s"); params.append(qs["week"])
    if qs.get("reviewerEmail"): where.append("lower(reviewer_email)=lower(%s)"); params.append(qs["reviewerEmail"])
    if role_rank(user["role"]) < 2:   # only Full sees everyone's assignments (blind calibration)
        where.append("lower(reviewer_email)=lower(%s)"); params.append(user["email"])
    w = ("WHERE " + " AND ".join(where)) if where else ""
    rows = db_all(f"SELECT * FROM calib_reviews {w} ORDER BY created_at", params)
    return {"reviews": [_review_api(r) for r in rows]}

def api_reviews_create(h, user, pp, qs, body):
    created, failed, ids = 0, 0, []
    with POOL.connection() as conn:
        for rv in body.get("reviews") or []:
            cols = _cols(REVIEW_FIELDS, rv)
            names = list(cols.keys())
            try:
                with conn.transaction():
                    r = conn.execute(f"INSERT INTO calib_reviews ({', '.join(names)}, app_updated_at) "
                                     f"VALUES ({', '.join(['%s'] * len(names))}, now()) RETURNING id", list(cols.values())).fetchone()
                ids.append(str(r["id"])); created += 1
            except Exception as e:
                failed += 1; print(f"[Calib] review insert failed: {e}")
    return {"created": created, "failed": failed, "ids": ids}

def api_review_patch(h, user, pp, qs, body):
    if not is_uuid(pp["id"]): raise ApiError(404, "review not found")
    r = db_one("SELECT reviewer_email FROM calib_reviews WHERE id=%s", (pp["id"],))
    if not r: raise ApiError(404, "review not found")
    if role_rank(user["role"]) < 2 and (r["reviewer_email"] or "").lower() != user["email"]:
        raise ApiError(403, "not your assignment")
    cols = _cols(REVIEW_FIELDS, body)
    if not cols: return {"ok": True}
    sets = ", ".join(f"{c}=%s" for c in cols)
    db_exec(f"UPDATE calib_reviews SET {sets}, updated_at=now(), app_updated_at=now() WHERE id=%s", list(cols.values()) + [pp["id"]])
    return {"ok": True}

# ── Admin: import / verify / cutover / snapshots ──────────────────────────────
def _job_view(j):
    if not j: return None
    return {k: j[k] for k in ("kind", "by", "running", "startedAt", "finishedAt", "phase", "progress", "log", "error", "result", "runId")}

def api_admin_status(h, user, pp, qs, body):
    counts = {t: db_one(f"SELECT count(*) AS n FROM {t}")["n"]
              for t in ("qa_users", "tickets", "config", "reports", "calib_rounds", "calib_reviews", "ticket_snapshots")}
    snap = {r["snapshot_status"]: r["n"] for r in db_all("SELECT snapshot_status, count(*) AS n FROM tickets GROUP BY 1")}
    return {"serverVersion": SERVER_VERSION, "notionConfigured": bool(NOTION_TOKEN), "cutover": cutover_state(),
            "counts": counts, "snapshots": snap, "snapshotQueue": SNAP_Q.qsize(),
            "lastImport": last_run("import"), "lastVerify": last_run("verify"),
            "jobs": {"import": _job_view(JOBS["import"]), "verify": _job_view(JOBS["verify"])}}

def api_admin_import(h, user, pp, qs, body):
    if cutover_state().get("done"):
        raise ApiError(409, "Cutover is complete, so import is locked. Reopen migration mode first if you really need to "
                            "re-import (it overwrites Wingman edits to imported rows).")
    if not NOTION_TOKEN: raise ApiError(400, "NOTION_TOKEN is not set on the server")
    return {"job": _job_view(start_job("import", user["email"]))}

def api_admin_verify(h, user, pp, qs, body):
    if not NOTION_TOKEN: raise ApiError(400, "NOTION_TOKEN is not set on the server")
    return {"job": _job_view(start_job("verify", user["email"]))}

def api_admin_verify_report(h, user, pp, qs, body):
    if qs.get("id"):
        r = db_one("SELECT * FROM admin_runs WHERE id=%s AND kind='verify'", (int(qs["id"]),))
    else:
        r = db_one("SELECT * FROM admin_runs WHERE kind='verify' ORDER BY id DESC LIMIT 1")
    if not r: raise ApiError(404, "no verify run yet")
    return {"id": r["id"], "startedBy": r["started_by"], "startedAt": r["started_at"], "finishedAt": r["finished_at"],
            "status": r["status"], "passed": r["passed"], "summary": r["summary"], "detail": r["detail"]}

def api_admin_cutover(h, user, pp, qs, body):
    if bool(body.get("done")):
        lv, li = last_run("verify"), last_run("import")
        if not lv or lv["status"] != "done" or not lv["passed"]:
            raise ApiError(409, "The latest verify run has not passed")
        if li and li["startedAt"] and lv["startedAt"] and lv["startedAt"] < li["startedAt"]:
            raise ApiError(409, "An import ran after the last verify — verify again first")
        state_set("cutover", {"done": True, "at": now_iso(), "by": user["email"], "verifyRunId": lv["id"]})
    else:
        if body.get("confirm") != "REOPEN":
            raise ApiError(400, "send confirm: 'REOPEN' to reopen migration mode")
        state_set("cutover", {"done": False, "reopenedAt": now_iso(), "by": user["email"]})
    return {"cutover": cutover_state()}

def api_admin_snapshot_retry(h, user, pp, qs, body):
    db_exec("UPDATE tickets SET snapshot_attempts=0 WHERE snapshot_status='failed'")
    return {"requeued": requeue_pending_snapshots()}

def api_gorgias_fields(h, user, pp, qs, body):
    return get_ctf_field_options(force=(qs.get("refresh") == "1" and role_rank(user["role"]) >= 2))

# ── Saved dashboard insights (v3.4.0) — Edit/Full only ─────────────────────────
def _insight_api(r, full=True):
    out = {"id": str(r["id"]), "createdAt": r["created_at"].isoformat(), "createdBy": r["created_by"],
           "dateFrom": r["date_from"], "dateTo": r["date_to"], "auditCount": r["audit_count"],
           "matrixVersion": r["matrix_version"]}
    if full:
        out["content"] = r["content"]; out["stats"] = r.get("stats")
    return out

def api_insights_list(h, user, pp, qs, body):
    rows = db_all("SELECT id, created_at, created_by, date_from, date_to, audit_count, matrix_version, content FROM insights ORDER BY created_at DESC LIMIT 100")
    return {"insights": [_insight_api(r) for r in rows]}   # list omits the stats payload

def api_insight_get(h, user, pp, qs, body):
    if not is_uuid(pp["id"]): raise ApiError(404, "insight not found")
    r = db_one("SELECT * FROM insights WHERE id=%s", (pp["id"],))
    if not r: raise ApiError(404, "insight not found")
    return _insight_api(r)

def api_insight_create(h, user, pp, qs, body):
    content = body.get("content")
    if not isinstance(content, dict) or not (content.get("wentWell") or content.get("improve")):
        raise ApiError(400, "content with wentWell/improve required")
    r = db_one("""INSERT INTO insights (created_by, date_from, date_to, audit_count, matrix_version, content, stats)
                  VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
               (user["name"], c_text(body.get("dateFrom")), c_text(body.get("dateTo")), c_int(body.get("auditCount")) or 0,
                c_int(body.get("matrixVersion")), Jsonb(content), Jsonb(body.get("stats")) if body.get("stats") is not None else None))
    return _insight_api(r)

def api_insight_delete(h, user, pp, qs, body):
    if not is_uuid(pp["id"]): raise ApiError(404, "insight not found")
    db_exec("DELETE FROM insights WHERE id=%s", (pp["id"],))
    return {"ok": True}

UUID_RX = r"(?P<id>[0-9a-fA-F-]{32,36})"
KEY_RX  = r"(?P<key>[A-Za-z0-9_.\-]+)"
# (method, path regex, fn, min role rank, is_write).  Writes are refused until cutover.
ROUTES = [
    ("GET",    r"/me",                                api_me,                   0, False),
    ("GET",    r"/gorgias/fields",                    api_gorgias_fields,       0, False),
    ("GET",    r"/settings/autofail-window",          api_autofail_window_get,  0, False),
    ("PUT",    r"/settings/autofail-window",          api_autofail_window_put,  2, True),
    ("GET",    r"/users",                             api_users_list,           0, False),
    ("POST",   r"/users",                             api_users_create,         2, True),
    ("PATCH",  r"/users/" + UUID_RX,                  api_users_update,         2, True),
    ("DELETE", r"/users/" + UUID_RX,                  api_users_delete,         2, True),
    ("GET",    r"/tickets",                           api_tickets_list,         0, False),
    ("GET",    r"/tickets/deleted-ids",               api_tickets_deleted_ids,  0, False),
    ("POST",   r"/tickets",                           api_ticket_create,        1, True),
    ("GET",    r"/tickets/" + UUID_RX + r"/snapshot", api_ticket_snapshot,      1, False),
    ("GET",    r"/tickets/" + UUID_RX,                api_ticket_get,           0, False),
    ("PATCH",  r"/tickets/" + UUID_RX,                api_ticket_patch,         0, True),
    ("GET",    r"/config/" + KEY_RX + r"/history",    api_config_history,       1, False),
    ("GET",    r"/config/" + KEY_RX,                  api_config_get,           0, False),
    ("PUT",    r"/config/" + KEY_RX,                  api_config_put,           2, True),   # v3.2.0: Full only (matrix, autofails, context, baseline)
    ("GET",    r"/reports",                           api_reports_list,         0, False),
    ("PUT",    r"/reports",                           api_reports_put,          1, True),
    ("GET",    r"/calib/rounds",                      api_rounds_list,          1, False),
    ("POST",   r"/calib/rounds",                      api_round_create,         1, True),
    ("GET",    r"/calib/rounds/" + UUID_RX,           api_round_get,            1, False),
    ("PATCH",  r"/calib/rounds/" + UUID_RX,           api_round_patch,          1, True),
    ("GET",    r"/calib/reviews",                     api_reviews_list,         1, False),
    ("POST",   r"/calib/reviews",                     api_reviews_create,       1, True),
    ("PATCH",  r"/calib/reviews/" + UUID_RX,          api_review_patch,         1, True),
    ("GET",    r"/insights",                          api_insights_list,        1, False),
    ("POST",   r"/insights",                          api_insight_create,       1, True),
    ("GET",    r"/insights/" + UUID_RX,               api_insight_get,          1, False),
    ("DELETE", r"/insights/" + UUID_RX,               api_insight_delete,       2, True),
    ("GET",    r"/admin/status",                      api_admin_status,         2, False),
    ("POST",   r"/admin/import",                      api_admin_import,         2, False),
    ("POST",   r"/admin/verify",                      api_admin_verify,         2, False),
    ("GET",    r"/admin/verify/report",               api_admin_verify_report,  2, False),
    ("POST",   r"/admin/cutover",                     api_admin_cutover,        2, False),
    ("POST",   r"/admin/snapshots/retry",             api_admin_snapshot_retry, 2, False),
]

# ══════════════════════════════════════════════════════════════════════════════
#  REQUEST HANDLER
# ══════════════════════════════════════════════════════════════════════════════

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

    def _session(self):
        """Return the verified session for this request, or None. Reads token from
        X-Session-Token header (preferred) or Authorization: Bearer fallback."""
        tok = self.headers.get("X-Session-Token", "")
        if not tok:
            tok = self.headers.get("Authorization", "").replace("Bearer ", "")
        return verify_session(tok.strip())

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Session-Token")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")

    def _json(self, data, status=200):
        msg = json.dumps(data, default=str).encode()
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(msg)))
        self.end_headers()
        self.wfile.write(msg)

    def _html(self, data: bytes, status=200):
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        if not raw: return {}
        try:
            body = json.loads(raw)
        except Exception:
            raise ApiError(400, "invalid JSON body")
        if not isinstance(body, dict): raise ApiError(400, "JSON body must be an object")
        return body

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    # ── /api router ───────────────────────────────────────────────────────────
    def _api(self, method):
        parsed = urlparse(self.path)
        path = parsed.path[len("/api"):] or "/"
        qs = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        try:
            if POOL is None:
                raise ApiError(503, "Database unavailable: " + (DB_ERROR or "not initialised"))
            sess = self._session()
            if not sess:
                raise ApiError(401, "unauthorized")
            user = resolve_user(sess["email"])
            if not user:
                raise ApiError(403, "not a Wingman user")
            if user.get("active") is False:
                raise ApiError(403, "account inactive")
            user = dict(user, picture=sess.get("picture", ""))   # avatar for /api/me (never stored in the DB)
            for (m, rx, fn, min_rank, is_write) in ROUTES:
                if m != method: continue
                mt = re.fullmatch(rx, path)
                if not mt: continue
                if role_rank(user["role"]) < min_rank:
                    raise ApiError(403, "insufficient role")
                if is_write and not cutover_state().get("done"):
                    raise ApiError(423, "Wingman is in migration mode — writes are disabled until the Notion import "
                                        "is verified and cutover is marked complete (Settings > Database).")
                body = self._body() if method in ("POST", "PUT", "PATCH") else {}
                result = fn(self, user, mt.groupdict(), qs, body)
                self._json(result if result is not None else {"ok": True})
                return
            raise ApiError(404, f"no route {method} {path}")
        except ApiError as e:
            self._json({"error": e.msg}, e.status)
        except Exception as e:
            traceback.print_exc()
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    def do_PUT(self):
        if self.path.startswith("/api/"): return self._api("PUT")
        self.send_response(404); self.end_headers()

    def do_PATCH(self):
        if self.path.startswith("/api/"): return self._api("PATCH")
        self.send_response(404); self.end_headers()

    def do_DELETE(self):
        if self.path.startswith("/api/"): return self._api("DELETE")
        self.send_response(404); self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        qs     = parse_qs(parsed.query)

        if path.startswith("/api/"):
            return self._api("GET")

        # ── Version ───────────────────────────────────────────────────────
        if path == "/version":
            self._json({
                "version": get_version(),
                "server":  SERVER_VERSION,
                "file":    os.path.join(DIR, HTML_FILE),
                "exists":  os.path.isfile(os.path.join(DIR, HTML_FILE)),
                "db":      "ok" if POOL is not None else ("error: " + DB_ERROR),
            })
            return

        # ── Google OAuth: initiate ────────────────────────────────────────
        if path == "/auth/google":
            if not GOOGLE_CLIENT_ID:
                self._json({"error": "Google SSO not configured"}, 500)
                return
            state = secrets.token_urlsafe(16)
            OAUTH_STATES[state] = time.time()
            params = urlencode({
                "client_id":     GOOGLE_CLIENT_ID,
                "redirect_uri":  REDIRECT_URI,
                "response_type": "code",
                "scope":         "openid email profile",
                "state":         state,
                "access_type":   "online",
                "hd":            "myfreebird.com"
            })
            self._redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")
            return

        # ── Google OAuth: callback ────────────────────────────────────────
        if path == "/auth/callback":
            code  = qs.get("code",  [""])[0]
            state = qs.get("state", [""])[0]
            error = qs.get("error", [""])[0]

            if error:
                self._redirect(f"{BASE_URL}/?auth_error={error}")
                return

            state_time = OAUTH_STATES.pop(state, None)
            if not state_time or (time.time() - state_time) > OAUTH_STATE_TTL:
                self._redirect(f"{BASE_URL}/?auth_error=invalid_state")
                return

            try:
                token_data   = google_get_token(code)
                access_token = token_data.get("access_token")
                if not access_token:
                    raise Exception("No access token")
                userinfo = google_get_userinfo(access_token)
                email    = userinfo.get("email", "").lower().strip()
                name     = userinfo.get("name", email.split("@")[0])
                if not email:
                    raise Exception("No email returned")
                session_token = create_session(email, name, via="google", picture=userinfo.get("picture", ""))
                self._redirect(f"{BASE_URL}/?session={session_token}")
            except Exception as e:
                print(f"[SSO] Auth error: {e}")
                self._redirect(f"{BASE_URL}/?auth_error=auth_failed")
            return

        # ── Session verify ────────────────────────────────────────────────
        if path == "/auth/verify":
            auth_header = self.headers.get("Authorization", "")
            token = auth_header.replace("Bearer ", "").strip()
            if not token:
                token = qs.get("token", [""])[0]
            session = verify_session(token)
            if session:
                self._json({"ok": True, "email": session["email"], "name": session["name"]})
            else:
                self._json({"ok": False, "error": "Invalid or expired session"}, 401)
            return

        # ── Emergency login page (GET) ────────────────────────────────────
        if path == "/emergency":
            html, status = render_emergency()
            self._html(html, status)
            return

        # ── App page (the ONLY static file served — never server.py, schema.sql, etc.) ──
        if path in ("/", "/index.html", "/" + HTML_FILE):
            filepath = os.path.join(DIR, HTML_FILE)
            if os.path.isfile(filepath):
                with open(filepath, "rb") as f:
                    data = inject_env(f.read())
                self._html(data)
                return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        if path.startswith("/api/"):
            return self._api("POST")

        # ── Session logout ────────────────────────────────────────────────
        if path == "/auth/logout":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                token = json.loads(raw).get("token", "")
                with SESSIONS_LOCK:
                    SESSIONS.pop(token, None)
            except:
                pass
            self._json({"ok": True})
            return

        # ── Emergency login (POST) ────────────────────────────────────────
        if path == "/emergency":
            length = int(self.headers.get("Content-Length", 0))
            raw    = self.rfile.read(length) if length else b""
            form   = parse_form(raw)

            submitted_email = form.get("email", "").strip().lower()
            submitted_pin   = form.get("pin",   "").strip()

            # PIN must be configured
            if not EMERGENCY_PIN:
                html, status = render_emergency("Emergency login is not configured. Contact your admin.")
                self._html(html, 403)
                return

            # All three checks must pass — use constant-time compare for PIN
            pin_ok    = secrets.compare_digest(submitted_pin, EMERGENCY_PIN)
            domain    = submitted_email.split("@")[-1] if "@" in submitted_email else ""
            domain_ok = domain in ALLOWED_DOMAINS
            user      = find_user_by_email(submitted_email) if (pin_ok and domain_ok) else None

            if not (pin_ok and domain_ok and submitted_email and user):
                html, status = render_emergency("Invalid email or PIN.")
                self._html(html, 401)
                return

            name          = user.get("name", submitted_email.split("@")[0].replace(".", " ").title())
            session_token = create_session(submitted_email, name, via="emergency")
            self._redirect(f"{BASE_URL}/?session={session_token}")
            return

        # ── Gorgias proxy ─────────────────────────────────────────────────
        if path == "/gorgias":
            if not self._session():
                self._json({"error": "unauthorized"}, 401)
                return
            if not GORGIAS_USERNAME or not GORGIAS_API_KEY:
                self._json({"error": "Gorgias credentials not configured"}, 500)
                return
            length = int(self.headers.get("Content-Length", 0))
            raw    = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw)
            except:
                body = {}
            endpoint = body.get("endpoint", "")
            params   = body.get("params", {})
            g_method = body.get("method", "GET")
            payload  = body.get("body")
            if not endpoint:
                self._json({"error": "endpoint required"}, 400)
                return
            url = f"https://{GORGIAS_DOMAIN}/api{endpoint}"
            if params:
                url += "?" + urlencode({k: v for k, v in params.items() if v is not None})
            creds = base64.b64encode(f"{GORGIAS_USERNAME}:{GORGIAS_API_KEY}".encode()).decode()
            fwd_headers = {
                "Authorization": f"Basic {creds}",
                "Content-Type":  "application/json",
                "User-Agent":    "FG-QA-Tool/1.0 (internal)",
                "Accept":        "application/json"
            }
            try:
                body_bytes = json.dumps(payload).encode() if payload else None
                req  = urllib.request.Request(url, data=body_bytes, headers=fwd_headers, method=g_method)
                resp = urllib.request.urlopen(req, timeout=30)
                data = resp.read()
                self.send_response(resp.status)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except urllib.error.HTTPError as e:
                data = e.read()
                self.send_response(e.code)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self._json({"error": str(e)}, 502)
            return

        # ── General proxy (Anthropic only, session-gated) ─────────────────
        if not self.path.startswith("/proxy"):
            self.send_response(404)
            self.end_headers()
            return

        # Require a valid session — the proxy holds the real API key
        if not self._session():
            self._json({"error": "unauthorized"}, 401)
            return

        qs     = parse_qs(urlparse(self.path).query)
        target = unquote(qs.get("url", [""])[0])
        if not target.startswith("https://"):
            self._json({"error": "bad url"}, 400)
            return

        # Host allowlist — prevents SSRF / open-relay abuse
        host = urlparse(target).hostname or ""
        if host not in PROXY_ALLOWED_HOSTS:
            self._json({"error": f"host not allowed: {host}"}, 403)
            return

        length     = int(self.headers.get("Content-Length", 0))
        raw        = self.rfile.read(length) if length else b"{}"
        try:    wrapper = json.loads(raw)
        except: wrapper = {}

        method     = wrapper.get("_method", "POST")
        body_obj   = wrapper.get("_body")
        body_bytes = json.dumps(body_obj).encode() if body_obj is not None else None

        # Credentials are injected SERVER-SIDE; client-supplied auth headers are ignored.
        fwd = {"Content-Type": "application/json",
               "x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01"}

        try:
            req  = urllib.request.Request(target, data=body_bytes, headers=fwd, method=method)
            resp = urllib.request.urlopen(req, timeout=120)
            data = resp.read()
            self.send_response(resp.status)
            self._cors()
            self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._json({"error": str(e)}, 502)

class Server(ThreadingHTTPServer):
    daemon_threads = True

if __name__ == "__main__":
    print(f"Starting Wingman server {SERVER_VERSION} on port {PORT}")
    print(f"Serving from: {DIR}")
    print(f"HTML version: {get_version()}")
    print(f"HTML exists: {os.path.isfile(os.path.join(DIR, HTML_FILE))}")
    print(f"Google SSO: {'configured' if GOOGLE_CLIENT_ID else 'NOT configured'}")
    print(f"Gorgias: {'configured' if GORGIAS_USERNAME and GORGIAS_API_KEY else 'NOT configured'}")
    print(f"Emergency login: {'configured' if EMERGENCY_PIN else 'NOT configured — set EMERGENCY_PIN in Railway'}")
    print(f"Notion (import/verify only): {'configured' if NOTION_TOKEN else 'not set'}")
    db_init()
    if POOL is not None:
        print(f"Cutover: {cutover_state()}")
        print(f"Snapshots requeued: {requeue_pending_snapshots()}")
        migrate_autofail_zero()
        repair_autofail_objects()
    threading.Thread(target=snapshot_worker, daemon=True).start()
    threading.Thread(target=get_ctf_field_options, daemon=True).start()   # warm the live CTF option cache
    Server(("0.0.0.0", PORT), Handler).serve_forever()
