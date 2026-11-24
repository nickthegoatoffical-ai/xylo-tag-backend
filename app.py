import os, sys, re, time, hmac, secrets, base64, hashlib, json, logging, threading
from collections import deque
from functools import wraps
import requests
from flask import Flask, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("xylotag")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # reject oversized bodies

# If you're behind a reverse proxy (Render, Railway, Cloudflare...), set this to the
# number of proxies in front of you so client IPs can't be spoofed via X-Forwarded-For.
TRUSTED_PROXY_HOPS = int(os.getenv("TRUSTED_PROXY_HOPS", "0"))
if TRUSTED_PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXY_HOPS)


def require_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"Missing environment variable: {name}. Set it in your host's dashboard.")
    return value


# ---------------------------------------------------------------- config
TITLE_ID = "B0BEA"  # Xylo Tag PlayFab title ID (the only value kept in the file)
PLAYFAB_SECRET_KEY = require_env("PLAYFAB_SECRET_KEY")
META_ACCESS_TOKEN = require_env("META_ACCESS_TOKEN")
EXPECTED_PACKAGE_ID = require_env("EXPECTED_PACKAGE_ID")


def normalize_cert(value):
    return str(value).replace(":", "").strip().lower()


EXPECTED_CERT_SHA256 = normalize_cert(require_env("META_CERT_SHA256"))

# Strict mode: set ALLOW_BASIC_DEVICE=false to only allow "Advanced" integrity devices.
ALLOW_BASIC_DEVICE = os.getenv("ALLOW_BASIC_DEVICE", "true").lower() == "true"
REQUIRE_ATTESTATION = os.getenv("REQUIRE_ATTESTATION", "true").lower() == "true"
# Require a valid attestation session on purchase consumption too (recommended).
REQUIRE_SESSION_FOR_IAP = os.getenv("REQUIRE_SESSION_FOR_IAP", "true").lower() == "true"
# Reject old/modded builds: set to the minimum allowed Android version code (0 = off).
MIN_APP_VERSION = int(os.getenv("MIN_APP_VERSION", "0"))
# Return failure reasons to clients only while debugging. Reasons help cheaters probe.
EXPOSE_REASONS = os.getenv("EXPOSE_REASONS", "false").lower() == "true"

CHALLENGE_TTL = 120
SESSION_TTL = int(os.getenv("SESSION_TTL", "1800"))  # short-lived; client must re-attest
MAX_OUTSTANDING_CHALLENGES_PER_ID = 5
MAX_NAME_LEN = int(os.getenv("MAX_NAME_LEN", "12"))
META_VERIFY_URL = "https://graph.oculus.com/platform_integrity/verify"

# Strike system: too many failures from an IP or account => temporary block.
STRIKE_LIMIT = 8
STRIKE_WINDOW = 600
BLOCK_SECONDS = 900

# Sessions are stateless HMAC-signed tokens, so they work across multiple workers
# and restarts. SET SESSION_SECRET in production (any long random string).
SESSION_SECRET = require_env("SESSION_SECRET").encode()  # any long random string

META_VERIFY_URL = "https://graph.oculus.com/platform_integrity/verify"

# In-memory state. Use Redis for production / multiple workers (challenges, rate
# limits and strikes are per-process here).
_challenges = {}
_rate = {}
_strikes = {}
_blocked = {}
_lock = threading.Lock()

ID_RE = re.compile(r"^[0-9A-Za-z_-]{1,64}$")


# ---------------------------------------------------------------- helpers
def playfab_headers():
    return {"Content-Type": "application/json", "X-SecretKey": PLAYFAB_SECRET_KEY}


def _b64url_decode(value):
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def client_ip():
    return request.remote_addr or "unknown"


def clean_id(value):
    """Accept only sane account IDs; returns str or None."""
    if value is None:
        return None
    value = str(value).strip()
    return value if ID_RE.match(value) else None


def fail_response(message, status, reason=None):
    body = {"Message": message}
    if reason and EXPOSE_REASONS:
        body["Reason"] = reason
    return jsonify(body), status


# ---------------------------------------------------------------- rate limiting / strikes
def rate_limited(key, limit, window):
    now = time.time()
    with _lock:
        if len(_rate) > 20000:  # opportunistic cleanup
            for k, q in list(_rate.items()):
                if not q or q[-1] < now - 300:
                    _rate.pop(k, None)
        q = _rate.setdefault(key, deque())
        while q and q[0] <= now - window:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now)
        return False


def is_blocked(*keys):
    now = time.time()
    with _lock:
        for key in keys:
            until = _blocked.get(key)
            if until and until > now:
                return True
            if until:
                _blocked.pop(key, None)
    return False


def add_strike(*keys):
    now = time.time()
    with _lock:
        for key in keys:
            if not key:
                continue
            q = _strikes.setdefault(key, deque())
            while q and q[0] <= now - STRIKE_WINDOW:
                q.popleft()
            q.append(now)
            if len(q) >= STRIKE_LIMIT:
                _blocked[key] = now + BLOCK_SECONDS
                q.clear()
                log.warning("blocked %s for %ss after repeated failures", key, BLOCK_SECONDS)
                send_log("Temporarily blocked (repeated failures)", RED, Target=key, Seconds=BLOCK_SECONDS)


def guard(limit=30, window=60):
    """Per-IP rate limit + block check for an endpoint."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip = client_ip()
            if is_blocked(f"ip:{ip}"):
                return jsonify({"Message": "Too many failed attempts. Try again later."}), 429
            if rate_limited(f"{fn.__name__}:{ip}", limit, window):
                return jsonify({"Message": "Rate limit exceeded"}), 429
            return fn(*args, **kwargs)
        return wrapper
    return deco


def record_failure(oculus_id, reason):
    log.warning("auth failure ip=%s id=%s reason=%s", client_ip(), oculus_id, reason)
    send_log("Attestation / auth FAILED", RED, Oculus_ID=oculus_id, Reason=reason, IP=client_ip())
    add_strike(f"ip:{client_ip()}", f"id:{oculus_id}" if oculus_id else None)


# ---------------------------------------------------------------- Discord logs
# Set DISCORD_WEBHOOK_URL in your host's environment variables. Leave it unset to disable logs.
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "").strip()


def send_log(title, color, **fields):
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        embed = {
            "title": title[:250],
            "color": color,
            "fields": [{"name": k.replace("_", " ")[:200], "value": ("`" + str(v)[:900] + "`") if v not in (None, "") else "`-`",
                        "inline": True} for k, v in fields.items()],
            "footer": {"text": "Xylo Tag"},
        }
        r = requests.post(DISCORD_WEBHOOK_URL, json={"username": "Xylo Tag Logs", "embeds": [embed]}, timeout=4)
        if r.status_code >= 300:
            log.warning("discord log rejected: HTTP %s %s", r.status_code, r.text[:200])
        return r.status_code
    except Exception as exc:  # never let logging break the game
        log.warning("discord log failed: %s", exc)
        return None


GREEN, RED, ORANGE, BLUE = 0x2ECC71, 0xE74C3C, 0xE67E22, 0x3498DB


# ---------------------------------------------------------------- anti-lib
# Detects mod/cheat-library fingerprints in anything the client sends (usernames,
# custom properties, mod lists, extra injected fields). Modes:
#   off     -> disabled
#   log     -> only log detections (use this first to check for false positives)
#   enforce -> reject the request and temporarily block the account/IP
ANTI_LIB_MODE = os.getenv("ANTI_LIB_MODE", "enforce").lower()
# Also reject /api/photon payloads containing fields your real client never sends.
ANTI_LIB_STRICT_KEYS = os.getenv("ANTI_LIB_STRICT_KEYS", "false").lower() == "true"
ANTI_LIB_ID_BLOCK_SECONDS = int(os.getenv("ANTI_LIB_ID_BLOCK_SECONDS", "86400"))
ANTI_LIB_IP_BLOCK_SECONDS = int(os.getenv("ANTI_LIB_IP_BLOCK_SECONDS", "900"))

_DEFAULT_SIGNATURES = {
    "bepinex", "melonloader", "monomod", "utilla", "cheatengine", "speedhack",
    "cheatmenu", "modmenu", "stupidmenu", "iimenu", "iisstupid", "violetmenu",
    "genesismenu", "ghostmenu", "steadymenu", "orangemenu", "noclip", "flymod",
}
# Add your own with ANTI_LIB_SIGNATURES="sigone,sigtwo" (min 5 chars each).
_EXTRA_SIGNATURES = set(os.getenv("ANTI_LIB_SIGNATURES", "").split(","))


def _squash(text):
    return re.sub(r"[^a-z0-9]", "", str(text).lower())


ANTI_LIB_SIGNATURES = {s for s in (_squash(x) for x in (_DEFAULT_SIGNATURES | _EXTRA_SIGNATURES))
                       if len(s) >= 5}

# Never scan secrets / random blobs.
_SCAN_SKIP_KEYS = {"IntegrityToken", "AttestationSession", "SessionTicket", "Ticket",
                   "Token", "Nonce", "nonce", "FunctionResult"}

KNOWN_PHOTON_KEYS = {
    "UserId", "AppId", "AppVersion", "Ticket", "Token", "Nonce", "Platform", "Username",
    "PlayerRoomCount", "GorillaTagger", "CosmeticAuthenticationV2", "CosmeticsInRoom",
    "UpdatePlayerCosmetics", "DLCOwnerShipV2", "GorillaCorpCurrencyV1", "RoomJoined",
    "VirtualStump", "DeadMonke", "GhostCounter", "BroadcastMyRoomV2", "TaggedClient",
    "TaggedDistance", "RPCS", "OculusId", "OCULUSId", "AttestationSession",
}


def _walk_strings(obj, depth=0):
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:200]:
            if k in _SCAN_SKIP_KEYS:
                continue
            yield str(k)[:256]
            yield from _walk_strings(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj[:200]:
            yield from _walk_strings(v, depth + 1)
    elif isinstance(obj, str):
        yield obj[:512]


# Libraries you trust. Set ANTI_LIB_ALLOWLIST="utilla,mygoodlib" to exempt them.
# Allowed names are removed from the text before scanning, so they can't trigger a
# detection (even if a blocked signature is a substring of an allowed name), while a
# blocked signature appearing alongside them still does.
ANTI_LIB_ALLOWLIST = {s for s in (_squash(x) for x in os.getenv("ANTI_LIB_ALLOWLIST", "").split(","))
                      if s}
_ALLOW_SORTED = sorted(ANTI_LIB_ALLOWLIST, key=len, reverse=True)


def find_cheat_signature(data):
    for text in _walk_strings(data):
        squashed = _squash(text)
        for allowed in _ALLOW_SORTED:
            squashed = squashed.replace(allowed, "")
        for sig in ANTI_LIB_SIGNATURES:
            if sig in squashed:
                return sig
    return None


@app.before_request
def anti_lib_gate():
    if (ANTI_LIB_MODE == "off" or request.method != "POST"
            or not request.path.startswith("/api/")
            or request.path == "/api/CheckForBadName"):
        return None
    data = request.get_json(silent=True)
    if not isinstance(data, (dict, list)):
        return None

    oculus_id = None
    if isinstance(data, dict):
        oculus_id = clean_id(data.get("OculusId") or data.get("OCULUSId") or data.get("userID"))
    if oculus_id and is_blocked(f"id:{oculus_id}"):
        return jsonify({"Message": "Request rejected"}), 403

    hit = find_cheat_signature(data)
    unknown = []
    if request.path == "/api/photon" and isinstance(data, dict):
        unknown = sorted(k for k in data if k not in KNOWN_PHOTON_KEYS)

    if hit is None and not (unknown and ANTI_LIB_STRICT_KEYS):
        if unknown:
            log.info("photon payload has unexpected keys: %s", unknown[:10])
        return None

    reason = f"signature:{hit}" if hit else f"unexpected_keys:{unknown[:5]}"
    log.warning("anti-lib detection ip=%s id=%s %s mode=%s", client_ip(), oculus_id, reason, ANTI_LIB_MODE)
    send_log("Anti-lib detection", ORANGE, Oculus_ID=oculus_id, Reason=reason, Mode=ANTI_LIB_MODE,
             Path=request.path, IP=client_ip())
    if ANTI_LIB_MODE != "enforce":
        return None
    now = time.time()
    with _lock:
        _blocked[f"ip:{client_ip()}"] = now + ANTI_LIB_IP_BLOCK_SECONDS
        if oculus_id:
            _blocked[f"id:{oculus_id}"] = now + ANTI_LIB_ID_BLOCK_SECONDS
    return jsonify({"Message": "Request rejected"}), 403


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers.pop("Server", None)
    return resp


# ---------------------------------------------------------------- challenges
# Stateless signed nonces so challenge + verify can hit different serverless instances.
def _sign(payload):
    return _b64url_encode(hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).digest())[:22]


def issue_challenge(oculus_id):
    exp = int(time.time()) + CHALLENGE_TTL
    payload = _b64url_encode(f"{oculus_id}|{exp}|{secrets.token_hex(8)}".encode())
    return f"{payload}.{_sign(payload)}"


def take_challenge(nonce, oculus_id):
    """Validate the signed nonce (bound to this account, unexpired). Replay is blocked
    best-effort per instance; Meta's own token expiry covers the rest."""
    if not isinstance(nonce, str) or not nonce or len(nonce) > 200 or "." not in nonce:
        return False
    payload, _, sig = nonce.partition(".")
    if not hmac.compare_digest(sig, _sign(payload)):
        return False
    try:
        bound_id, exp, _rand = _b64url_decode(payload).decode().split("|")
        if bound_id != str(oculus_id) or int(exp) < time.time():
            return False
    except (ValueError, UnicodeDecodeError):
        return False
    with _lock:
        now = time.time()
        for k, v in list(_challenges.items()):
            if v < now:
                _challenges.pop(k, None)
        if nonce in _challenges:
            return False
        _challenges[nonce] = now + CHALLENGE_TTL
    return True


# ---------------------------------------------------------------- Meta verification
def verify_meta_token(integrity_token, expected_nonce):
    if not isinstance(integrity_token, str) or not integrity_token or len(integrity_token) > 16384:
        return False, {}, "missing_token"
    try:
        response = requests.get(
            META_VERIFY_URL,
            params={"token": integrity_token, "access_token": META_ACCESS_TOKEN},
            timeout=12,
        )
        response.raise_for_status()
        body = response.json()
        data = body.get("data", [])
        if not data or data[0].get("message") != "success" or not data[0].get("claims"):
            return False, {}, "meta_rejected_token"
        claims = json.loads(_b64url_decode(data[0]["claims"]).decode("utf-8"))
    except (requests.RequestException, ValueError, KeyError, TypeError, UnicodeDecodeError):
        return False, {}, "meta_verification_error"

    details = claims.get("request_details") or {}
    app_state = claims.get("app_state") or {}
    device_state = claims.get("device_state") or {}
    now = int(time.time())

    if not hmac.compare_digest(str(details.get("nonce", "")), expected_nonce):
        return False, {}, "nonce_mismatch"
    if not isinstance(details.get("exp"), (int, float)) or details["exp"] <= now:
        return False, {}, "token_expired"
    if not isinstance(details.get("timestamp"), (int, float)) or abs(now - details["timestamp"]) > 120:
        return False, {}, "token_timestamp_invalid"

    if EXPECTED_PACKAGE_ID and app_state.get("package_id") != EXPECTED_PACKAGE_ID:
        return False, {}, "package_id_mismatch"
    if EXPECTED_CERT_SHA256:
        certs = [normalize_cert(x) for x in (app_state.get("package_cert_sha256_digest") or [])]
        if EXPECTED_CERT_SHA256 not in certs:
            return False, {}, "signing_certificate_mismatch"

    if app_state.get("app_integrity_state") != "StoreRecognized":
        return False, {}, "app_not_store_recognized"

    if MIN_APP_VERSION:
        try:
            if int(app_state.get("version")) < MIN_APP_VERSION:
                return False, {}, "app_version_too_old"
        except (TypeError, ValueError):
            return False, {}, "app_version_missing"

    allowed_devices = {"Advanced", "Basic"} if ALLOW_BASIC_DEVICE else {"Advanced"}
    if device_state.get("device_integrity_state") not in allowed_devices:
        return False, {}, "device_not_trusted"
    if device_state.get("unlocked") is True:
        return False, {}, "device_unlocked"

    return True, claims, None


# ---------------------------------------------------------------- stateless sessions
def create_attestation_session(oculus_id, claims=None):
    token_exp = ((claims or {}).get("request_details") or {}).get("exp", 0)
    exp = int(min(int(token_exp) if token_exp else 10**12, time.time() + SESSION_TTL))
    payload = _b64url_encode(f"{oculus_id}|{exp}".encode())
    sig = _b64url_encode(hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def valid_attestation_session(session, oculus_id):
    """Session must be validly signed, unexpired, and bound to THIS account."""
    if not isinstance(session, str) or "." not in session or len(session) > 512 or not oculus_id:
        return False
    payload, _, sig = session.partition(".")
    expected = _b64url_encode(hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        bound_id, _, exp = _b64url_decode(payload).decode().rpartition("|")
        return bound_id == str(oculus_id) and int(exp) >= time.time()
    except (ValueError, UnicodeDecodeError):
        return False


def run_attestation(oculus_id, nonce, token):
    """Returns (session, error_reason)."""
    if not take_challenge(nonce, oculus_id):
        record_failure(oculus_id, "challenge_invalid")
        return None, "challenge_invalid"
    ok, claims, error = verify_meta_token(token, nonce)
    if not ok:
        record_failure(oculus_id, error)
        return None, error
    return create_attestation_session(oculus_id, claims), None


# ---------------------------------------------------------------- endpoints
@app.post("/api/attestation/challenge")
@guard(limit=20, window=60)
def attestation_challenge():
    data = request.get_json(silent=True) or {}
    oculus_id = clean_id(data.get("OculusId") or data.get("OCULUSId"))
    if not oculus_id:
        return jsonify({"Message": "OculusId is required"}), 400
    if is_blocked(f"id:{oculus_id}"):
        return jsonify({"Message": "Too many failed attempts. Try again later."}), 429
    nonce = issue_challenge(oculus_id)
    return jsonify({"Nonce": nonce, "ExpiresIn": CHALLENGE_TTL}), 200


@app.post("/api/attestation/verify")
@guard(limit=15, window=60)
def attestation_verify():
    data = request.get_json(silent=True) or {}
    oculus_id = clean_id(data.get("OculusId") or data.get("OCULUSId"))
    nonce, token = data.get("Nonce"), data.get("IntegrityToken")
    if not oculus_id or not isinstance(nonce, str) or not isinstance(token, str):
        return jsonify({"Message": "OculusId, Nonce and IntegrityToken are required"}), 400
    if is_blocked(f"id:{oculus_id}"):
        return jsonify({"Message": "Too many failed attempts. Try again later."}), 429
    session, error = run_attestation(oculus_id, nonce, token)
    if error:
        return fail_response("Attestation failed", 403, error)
    send_log("Attestation passed", GREEN, Oculus_ID=oculus_id)
    return jsonify({"Attested": True, "AttestationSession": session, "ExpiresIn": SESSION_TTL}), 200


@app.post("/api/PlayFabAuthentication")
@guard(limit=20, window=60)
def playfab_authentication():
    data = request.get_json(silent=True) or {}
    oculus_id = clean_id(data.get("OculusId") or data.get("OCULUSId"))
    nonce = data.get("Nonce")
    token = data.get("IntegrityToken")
    session = data.get("AttestationSession")
    if not oculus_id:
        return jsonify({"Message": "A valid OculusId is required"}), 400
    if is_blocked(f"id:{oculus_id}"):
        return jsonify({"Message": "Too many failed attempts. Try again later."}), 429

    if REQUIRE_ATTESTATION:
        if session:
            if not valid_attestation_session(session, oculus_id):
                record_failure(oculus_id, "bad_session")
                return fail_response("Attestation session invalid or expired", 403, "bad_session")
        else:
            if not isinstance(nonce, str) or not isinstance(token, str) or not nonce or not token:
                return jsonify({"Message": "Provide Nonce and IntegrityToken, or AttestationSession"}), 400
            session, error = run_attestation(oculus_id, nonce, token)
            if error:
                return fail_response("Attestation failed", 403, error)

    try:
        login = requests.post(
            f"https://{TITLE_ID}.playfabapi.com/Server/LoginWithServerCustomId",
            json={"ServerCustomId": f"OCULUS{oculus_id}", "CreateAccount": True},
            headers=playfab_headers(), timeout=12,
        )
        result = login.json()
    except (requests.RequestException, ValueError):
        return jsonify({"Message": "PlayFab unavailable"}), 502

    if login.status_code != 200:
        if result.get("errorCode") == 1002:
            details = result.get("errorDetails") or {}
            reason = next(iter(details.keys()), "Banned")
            expiration = (details.get(reason) or ["Indefinite"])[0]
            send_log("Banned player tried to log in", ORANGE, Oculus_ID=oculus_id, Ban_reason=reason, Expires=expiration)
            return jsonify({"BanMessage": reason, "BanExpirationTime": expiration}), 403
        send_log("PlayFab login failed", RED, Oculus_ID=oculus_id, PlayFab_error=result.get("errorMessage"))
        return jsonify({"Message": "Login failed"}), 403

    pf = result.get("data", {})
    ticket = pf.get("SessionTicket")
    if ticket:
        try:
            requests.post(
                f"https://{TITLE_ID}.playfabapi.com/Client/LinkCustomID",
                json={"CustomID": f"OCULUS{oculus_id}", "ForceLink": True},
                headers={"Content-Type": "application/json", "X-Authorization": ticket},
                timeout=10,
            )
        except requests.RequestException:
            pass
    entity = pf.get("EntityToken", {})
    send_log("Player logged in", GREEN, Oculus_ID=oculus_id, PlayFab_ID=pf.get("PlayFabId"),
             New_account=pf.get("NewlyCreated"), Platform=data.get("Platform", "QUEST"), IP=client_ip())
    return jsonify({
        "PlayFabId": pf.get("PlayFabId"),
        "SessionTicket": ticket,
        "EntityToken": entity.get("EntityToken"),
        "EntityId": entity.get("Entity", {}).get("Id"),
        "EntityType": entity.get("Entity", {}).get("Type"),
        "OculusId": oculus_id,
        "Platform": data.get("Platform", "QUEST"),
        "AttestationSession": session,
        "ExpiresIn": SESSION_TTL,
    }), 200


DEFAULT_MOTD = ("<color=#FF007F>WELCOME TO XYLO TAG!</color>\n"
                "<color=#00F0FF>OWNER IS RIZZUEJR</color>\n"
                "<color=#DDB3FF>UNBORN MADE THIS BACKEND</color>")


@app.post("/api/TD")
@guard(limit=60, window=60)
def titled_data():
    # Optional env var MOTD_TEXT overrides the message (use \n for new lines).
    custom = os.getenv("MOTD_TEXT", "").replace("\\n", "\n").strip()
    return jsonify({"MOTD": custom or DEFAULT_MOTD})


# ---------------------------------------------------------------- name filter
BAD_NAMES = {
    "KKK", "PENIS", "NIGG", "NEG", "NIGA", "MONKEYSLAVE", "SLAVE", "FAG", "NAGGI",
    "TRANNY", "QUEER", "KYS", "DICK", "PUSSY", "VAGINA", "BIGBLACKCOCK", "DILDO",
    "HITLER", "KKX", "XKK", "NIGE", "NIG", "NI6", "PORN", "JEW", "JAXX", "TTTPIG",
    "SEX", "COCK", "CUM", "FUCK", "ELLIOT", "JMAN", "K9", "NIGGA", "NICKER", "NICKA",
    "REEL", "NII", "@HERE", "!", " ", "PPPTIG", "CLEANINGBOT", "JANITOR", "H4PKY",
    "MOSA", "NIGGER", "IHATENIGGERS", "@EVERYONE", "TTT",
}
# Unambiguous words blocked anywhere inside a name (after leetspeak normalisation).
# Short words like CUM/SEX stay exact-match only to avoid false positives.
BAD_SUBSTRINGS = {"NIGGER", "NIGGA", "NIGGE", "FAGGOT", "HITLER", "TRANNY",
                  "BIGBLACKCOCK", "IHATENIGGERS", "MONKEYSLAVE", "DILDO", "FUCK"}
_LEET = str.maketrans({"0": "O", "1": "I", "3": "E", "4": "A", "5": "S", "7": "T",
                       "@": "A", "$": "S", "!": "I", "|": "I", "_": "", "-": "", ".": ""})
_ALPHA_BAD = {b for b in BAD_NAMES if b.isalpha()}


def name_is_bad(name):
    raw = name.upper()
    if raw in BAD_NAMES:
        return True
    norm = raw.translate(_LEET)
    collapsed = re.sub(r"(.)\1+", r"\1", norm)  # NIIGGGER -> NIGER-style evasions
    for candidate in (norm, collapsed):
        if candidate in _ALPHA_BAD:
            return True
        if any(bad in candidate for bad in BAD_SUBSTRINGS):
            return True
    return False


@app.post("/api/CheckForBadName")
@guard(limit=60, window=60)
def check_for_bad_name():
    data = request.get_json(silent=True) or {}
    result = data.get("FunctionResult") or {}
    name = str(result.get("name", "")).strip()
    if not name or len(name) > MAX_NAME_LEN or name_is_bad(name):
        send_log("Bad name rejected", BLUE, Name=name, IP=client_ip())
        return jsonify({"result": 2})
    return jsonify({"result": 0})


@app.post("/api/CachePlayFabId")
@guard(limit=30, window=60)
def cache_playfab_id():
    data = request.get_json(silent=True) or {}
    ticket = data.get("SessionTicket")
    if not isinstance(ticket, str) or not ticket or len(ticket) > 512:
        return jsonify({"Message": "Try Again Later."}), 404
    try:
        resp = requests.post(
            f"https://{TITLE_ID}.playfabapi.com/Server/AuthenticateSessionTicket",
            json={"SessionTicket": ticket},
            headers=playfab_headers(), timeout=12,
        )
        body = resp.json()
    except (requests.RequestException, ValueError):
        return jsonify({"Message": "PlayFab unavailable"}), 502
    if resp.status_code != 200:
        add_strike(f"ip:{client_ip()}")
        return jsonify({"Message": "Invalid session ticket"}), 403
    user = (body.get("data") or {}).get("UserInfo") or {}
    playfab_id = user.get("PlayFabId")
    if not playfab_id:
        add_strike(f"ip:{client_ip()}")
        return jsonify({"Message": "Invalid session ticket"}), 403
    return jsonify({"Message": "Cached", "PlayFabId": playfab_id}), 200


@app.post("/api/ConsumeOculusIAP")
@guard(limit=20, window=60)
def consume_oculus_iap():
    data = request.get_json(silent=True) or {}
    user_id, nonce, sku = clean_id(data.get("userID")), data.get("nonce"), data.get("sku")
    if not user_id or not nonce or not sku:
        return jsonify({"error": True}), 400
    if REQUIRE_ATTESTATION and REQUIRE_SESSION_FOR_IAP:
        if not valid_attestation_session(data.get("AttestationSession"), user_id):
            record_failure(user_id, "iap_no_session")
            return jsonify({"error": True, "Message": "Attestation required"}), 403
    try:
        response = requests.post(
            "https://graph.oculus.com/consume_entitlement",
            params={"nonce": nonce, "user_id": user_id, "sku": sku,
                    "access_token": META_ACCESS_TOKEN},
            timeout=12,
        )
        body = response.json()
    except (requests.RequestException, ValueError):
        return jsonify({"error": True}), 502
    success = bool(response.ok and body.get("success"))
    return jsonify({"result": success}), (200 if success else 403)


@app.route("/api/photon", methods=["GET", "POST"])
@guard(limit=60, window=60)
def photonauth():
    data = request.get_json(silent=True) or request.args.to_dict() or {}
    oculus_id = clean_id(data.get("OculusId") or data.get("OCULUSId"))
    if REQUIRE_ATTESTATION:
        if not oculus_id or not valid_attestation_session(data.get("AttestationSession"), oculus_id):
            record_failure(oculus_id, "photon_no_session")
            return jsonify({"ResultCode": 2, "StatusCode": 403, "Message": "Attestation required"}), 403
    return jsonify({
        "ResultCode": 1, "StatusCode": 200, "Message": "authed with photon",
        "Result": 0, "UserId": data.get("UserId"), "AppId": data.get("AppId"),
        "AppVersion": data.get("AppVersion"), "Ticket": data.get("Ticket"),
        "Token": data.get("Token"), "Nonce": data.get("Nonce"),
        "Platform": data.get("Platform"), "Username": data.get("Username"),
        "PlayerRoomCount": data.get("PlayerRoomCount"),
        "GorillaTagger": data.get("GorillaTagger"),
        "CosmeticAuthentication": data.get("CosmeticAuthenticationV2"),
        "CosmeticsInRoom": data.get("CosmeticsInRoom"),
        "UpdatePlayerCosmetics": data.get("UpdatePlayerCosmetics"),
        "DLCOwnerShip": data.get("DLCOwnerShipV2"),
        "Currency": data.get("GorillaCorpCurrencyV1"),
        "RoomJoined": data.get("RoomJoined"), "VirtualStump": data.get("VirtualStump"),
        "DeadMonke": data.get("DeadMonke"), "GhostCounter": data.get("GhostCounter"),
        "BroadcastRoom": data.get("BroadcastMyRoomV2"),
        "TaggedClient": data.get("TaggedClient"), "TaggedDistance": data.get("TaggedDistance"),
        "RPCS": data.get("RPCS"),
    }), 200


@app.get("/api/status")
def status():
    return jsonify({"online": True, "status": "BACKEND IS RUNNING", "titleId": TITLE_ID,
                    "webhookConfigured": bool(DISCORD_WEBHOOK_URL)})


@app.get("/api/testlog")
def test_log():
    """Open /api/testlog?key=<your SESSION_SECRET> to send a test message to your webhook."""
    if not hmac.compare_digest(request.args.get("key", ""), SESSION_SECRET.decode()):
        return jsonify({"Message": "Forbidden"}), 403
    if not DISCORD_WEBHOOK_URL:
        return jsonify({"sent": False, "reason": "DISCORD_WEBHOOK_URL is not set (or you did not redeploy)"}), 200
    code = send_log("Test log", BLUE, Message="If you can read this, logging works.")
    return jsonify({"sent": code is not None and code < 300, "discordHttpStatus": code}), 200


@app.get("/")
def main():
    return "Xylo Tag backend online", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
