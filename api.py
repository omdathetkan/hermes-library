"""
OCLC WISE library API client.

Handles:
  - Full OIDC PKCE login via KB iWelcome (login.kb.nl) → Keycloak (iam-emea.wise.oclc.org)
  - Catalog search (branch perspective endpoint)
  - Title availability
  - List holds / place hold

All API calls to bibliotheek.wise.oclc.org require the WISE_KEY header.
The UUID prefix is the library's static public client key; the 32-byte hex suffix
is a per-session random value generated client-side by the OPAC JS app.
"""

import base64
import hashlib
import hmac
import http.cookiejar
import json
import re
import secrets
import time
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta
from urllib.parse import parse_qs, urlparse

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _ssl_context() -> ssl.SSLContext:
    """
    Build an SSL context for HTTPS requests.

    Uses certifi's CA bundle when available (common on Windows Python installs
    where the system store is incomplete for some hosts like login.kb.nl).
    Falls back to the platform default otherwise — no extra package required.
    """
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


class _FixHostnameHTTPSHandler(urllib.request.HTTPSHandler):
    """Strip trailing dots from hostnames before SSL connects (Windows DNS fix)."""

    def __init__(self):
        super().__init__(context=_ssl_context())

    def https_open(self, req):
        host = req.host
        if ":" in host:
            h, p = host.rsplit(":", 1)
            req.host = h.rstrip(".") + ":" + p
        else:
            req.host = host.rstrip(".")
        return super().https_open(req)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _HttpResponse:
    def __init__(self, status: int, headers, body: bytes, url: str):
        self.status_code = status
        self.headers = headers
        self._body = body
        self.url = url

    @property
    def text(self) -> str:
        return self._body.decode("utf-8", errors="replace")

    def json(self) -> dict:
        return json.loads(self.text)

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(
                f"HTTP {self.status_code}: {self.text[:500]}"
            )


def _resolve_redirect(current_url: str, location: str) -> str:
    return urllib.parse.urljoin(current_url, location)


def _urlopen(req: urllib.request.Request, timeout: int = 15):
    host = req.host if hasattr(req, "host") else ""
    if host:
        if ":" in host:
            h, p = host.rsplit(":", 1)
            req.host = h.rstrip(".") + ":" + p
        else:
            req.host = host.rstrip(".")
    return urllib.request.build_opener(_FixHostnameHTTPSHandler()).open(req, timeout=timeout)


def _build_opener(*, follow_redirects: bool = True, cookies: bool = False):
    handlers: list = [_FixHostnameHTTPSHandler()]
    if cookies:
        handlers.insert(0, urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    if follow_redirects:
        handlers.append(urllib.request.HTTPRedirectHandler())
    else:
        handlers.append(_NoRedirectHandler())
    return urllib.request.build_opener(*handlers)


def _url_with_params(url: str, params: dict | None) -> str:
    if not params:
        return url
    query = urllib.parse.urlencode(params)
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{query}"


def _opener_request(
    opener: urllib.request.OpenerDirector,
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict | None = None,
    timeout: int = 30,
) -> _HttpResponse:
    req = urllib.request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return _HttpResponse(resp.status, resp.headers, resp.read(), resp.geturl())
    except urllib.error.HTTPError as exc:
        return _HttpResponse(exc.code, exc.headers, exc.read(), exc.geturl())


def _http_get(
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: int = 15,
    follow_redirects: bool = True,
) -> _HttpResponse:
    opener = _build_opener(follow_redirects=follow_redirects)
    return _opener_request(
        opener,
        _url_with_params(url, params),
        headers=headers,
        timeout=timeout,
    )


def _http_post(
    url: str,
    *,
    headers: dict | None = None,
    json_body: dict | None = None,
    form: dict | None = None,
    timeout: int = 30,
    opener: urllib.request.OpenerDirector | None = None,
) -> _HttpResponse:
    data = None
    hdrs = dict(headers or {})
    if json_body is not None:
        data = json.dumps(json_body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")

    if opener is None:
        opener = _build_opener()
    return _opener_request(opener, url, method="POST", data=data, headers=hdrs, timeout=timeout)


def _api_json(
    method: str,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    body: dict | None = None,
    timeout: int = 15,
) -> dict | list:
    full_url = _url_with_params(url, params)
    payload = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(full_url, data=payload, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    if payload is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with _urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail[:500]}") from exc

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WISE_BASE = "https://bibliotheek.wise.oclc.org/restapi"
KEYCLOAK_AUTH_URL = (
    "https://iam-emea.wise.oclc.org/realms/bibliotheek"
    "/protocol/openid-connect/auth"
)
TOKEN_URL = (
    "https://iam-emea.wise.oclc.org/realms/bibliotheek"
    "/protocol/openid-connect/token"
)
KB_LOGIN_URL = "https://login.kb.nl/si/login/api/authenticate"
OIDC_CLIENT_ID = "opac-via-external-idp"

# Perspective 3682 = default "all media" search perspective for this library.
SEARCH_PERSPECTIVE = "3682"

# WISE_KEY is a daily rotating HMAC-SHA256 token derived from credentials
# embedded in the OPAC JavaScript bundle.  We replicate the browser's algorithm:
#   epochDay    = floor(Date.now() / 86_400_000)   # UTC, not local calendar date
#   WISE_KEY    = f"{apiKeyId}:{HMAC-SHA256(key=apiKey, msg=f'{epochDay}{appName}')}"
# Credentials are fetched from the live main-*.js bundle (cached per process).
_WISE_APP_NAME = "Opac Branch"
_WISE_OPAC_BASE = "https://bibliotheek.wise.oclc.org/wise-apps/opac"
_WISE_CREDS_PATTERN = re.compile(
    r'\{apiKeyId:"([^"]+)",apiKey:"([^"]+)",applicationName:"Opac Branch"\}'
)

_wise_creds_cache: tuple[str, str] | None = None


def _fetch_wise_credentials(branch_id: str = "2850") -> tuple[str, str]:
    """
    Fetch apiKeyId and apiKey for 'Opac Branch' from the live OPAC JS bundle.
    Results are cached for the process lifetime.
    """
    global _wise_creds_cache
    if _wise_creds_cache is not None:
        return _wise_creds_cache

    headers = {
        "User-Agent": _BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,*/*",
    }
    page_url = f"{_WISE_OPAC_BASE}/branch/{branch_id}/catalog/search"
    r = _http_get(page_url, headers=headers, timeout=20)
    r.raise_for_status()

    m = re.search(r"main-[A-Z0-9]+\.js", r.text)
    if not m:
        raise RuntimeError("Could not find main-*.js in OPAC page")

    r = _http_get(
        f"{_WISE_OPAC_BASE}/{m.group(0)}",
        headers={**headers, "Referer": r.url, "Accept": "*/*"},
        timeout=30,
    )
    r.raise_for_status()

    cm = _WISE_CREDS_PATTERN.search(r.text)
    if not cm:
        raise RuntimeError("Could not find Opac Branch API credentials in OPAC JS bundle")

    _wise_creds_cache = (cm.group(1), cm.group(2))
    return _wise_creds_cache


def _compute_wise_key(branch_id: str) -> str:
    """Compute today's WISE_KEY using live OPAC credentials and the browser HMAC algorithm."""
    api_key_id, api_key = _fetch_wise_credentials(branch_id)
    epoch_day = int(time.time() // 86400)
    msg = f"{epoch_day}{_WISE_APP_NAME}"
    digest = hmac.new(api_key.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{api_key_id}:{digest}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_jwt_payload(token: str) -> dict:
    """Decode the payload section of a JWT without verifying the signature."""
    payload_b64 = token.split(".")[1]
    # Add padding so base64 decode doesn't fail.
    padding = 4 - len(payload_b64) % 4
    payload_b64 += "=" * (padding % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _extract_frbr_title_id(item: dict) -> str | None:
    """
    Recursively search a search-result item for an ID with the
    'FRBR!:T:{numeric_id}' format and return the numeric part.
    These IDs map directly to the bibliographicRecordId used by
    availability checks and hold placement.
    """
    def _walk(obj):
        if isinstance(obj, dict):
            item_id = obj.get("id", "")
            if isinstance(item_id, str) and item_id.startswith("FRBR!:T:"):
                return item_id.split(":")[-1]
            for v in obj.values():
                result = _walk(v)
                if result:
                    return result
        elif isinstance(obj, list):
            for elem in obj:
                result = _walk(elem)
                if result:
                    return result
        return None

    return _walk(item)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class LibraryClient:
    """
    Stateful client for one library session.
    Call `ensure_logged_in()` before any patron-scoped operation.
    Search and availability are public and do not require login.
    """

    def __init__(
        self,
        username: str,
        password: str,
        branch_id: str,
        library_id: str,
    ):
        self.username = username
        self.password = password
        self.branch_id = branch_id
        self.library_id = library_id
        self.wise_key = _compute_wise_key(branch_id)
        self._access_token: str | None = None
        self._patron_id: str | None = None
        self._redirect_uri = (
            f"https://bibliotheek.wise.oclc.org/wise-apps/opac"
            f"/branch/{branch_id}/my-account/checkouts/physical-materials"
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _headers(self, *, auth: bool = False) -> dict:
        h = {
            "WISE_KEY": self.wise_key,
            "Accept": "application/json",
            "User-Agent": _BROWSER_UA,
        }
        if auth and self._access_token:
            h["Authorization"] = f"Bearer {self._access_token}"
        return h

    def ensure_logged_in(self) -> None:
        if not self._access_token:
            self._login()

    def _login(self) -> None:
        """Perform the full OIDC PKCE login and populate _access_token / _patron_id."""
        code_verifier, code_challenge = _pkce_pair()
        state = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)

        opener = _build_opener(follow_redirects=False, cookies=True)
        opener.addheaders = [("User-Agent", _BROWSER_UA)]

        def _get(url: str, headers: dict | None = None) -> _HttpResponse:
            return _opener_request(opener, url, headers=headers, timeout=30)

        def _post(
            url: str,
            *,
            headers: dict | None = None,
            json_body: dict | None = None,
            form: dict | None = None,
        ) -> _HttpResponse:
            return _http_post(
                url,
                headers=headers,
                json_body=json_body,
                form=form,
                opener=opener,
                timeout=30,
            )

        # ── Step 1: initiate OIDC at Keycloak ─────────────────────────
        # Keycloak redirects through its broker to login.kb.nl
        r = _get(
            _url_with_params(
                KEYCLOAK_AUTH_URL,
                {
                    "response_type": "code",
                    "client_id": OIDC_CLIENT_ID,
                    "redirect_uri": self._redirect_uri,
                    "scope": "openid patron-actions",
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "state": state,
                    "nonce": nonce,
                },
            )
        )

        # Follow redirects until we land on the KB login page
        for _ in range(10):
            if not r.is_redirect:
                break
            location = r.headers.get("Location", "")
            r = _get(_resolve_redirect(r.url, location))
            if "login.kb.nl/si/login/" in r.url:
                break

        login_page_url = r.url

        # ── Step 2: extract goto_url, then POST credentials ────────────
        parsed = urlparse(login_page_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        goto_url = qs.get("goto", [""])[0]

        if not goto_url:
            raise RuntimeError(
                "Could not find goto parameter on KB login page. "
                f"Landed on: {login_page_url}"
            )

        r = _post(
            KB_LOGIN_URL,
            json_body={
                "module": "UsernameAndPassword",
                "definition": {
                    "rememberMe": False,
                    "username": self.username,
                    "password": self.password,
                },
            },
            headers={
                "Goto-Url": goto_url,
                "Referer": login_page_url,
                "Origin": "https://login.kb.nl",
            },
        )

        if r.status_code != 200:
            raise RuntimeError(
                f"KB login failed (HTTP {r.status_code}): {r.text[:500]}"
            )

        resp = r.json()
        if resp.get("nextModule") != "Success":
            msg = resp.get("message") or r.text[:200]
            raise RuntimeError(f"KB login rejected: {msg}")

        # ── Step 3: follow goto_url → Keycloak broker → redirect_uri?code= ──
        redirect_host = "bibliotheek.wise.oclc.org"
        r = _get(goto_url)
        code = None
        for _ in range(15):
            if not r.is_redirect:
                break
            location = _resolve_redirect(r.url, r.headers.get("Location", ""))
            if redirect_host in location:
                m = re.search(r"[?&]code=([^&#\s]+)", location)
                if m:
                    code = m.group(1)
                    break
            r = _get(location)

        if not code:
            raise RuntimeError(
                "OIDC flow completed but no authorization code was returned."
            )

        # ── Step 4: exchange code for tokens ──────────────────────────
        r = _post(
            TOKEN_URL,
            form={
                "grant_type": "authorization_code",
                "client_id": OIDC_CLIENT_ID,
                "redirect_uri": self._redirect_uri,
                "code": code,
                "code_verifier": code_verifier,
            },
        )

        if r.status_code != 200:
            raise RuntimeError(
                f"Token exchange failed (HTTP {r.status_code}): {r.text[:500]}"
            )

        token_data = r.json()
        self._access_token = token_data["access_token"]

        claims = _decode_jwt_payload(self._access_token)
        self._patron_id = claims.get("wiseUuid")

        if not self._patron_id:
            raise RuntimeError("Access token has no wiseUuid claim; cannot identify patron.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        scope: str = "title",
        limit: int = 10,
        offset: int = 0,
    ) -> dict:
        """
        Search the library catalog.

        scope: 'title' | 'author' | 'isbn'
        Returns dict with 'total' and 'results' list.
        Each result includes title_id (for availability / hold placement),
        title, author, year, media type, and ISBN.
        """
        # Search requires both WISE_KEY and Bearer token.
        self.ensure_logged_in()
        data = _api_json(
            "GET",
            f"{WISE_BASE}/branch/{self.branch_id}"
            f"/perspective/{SEARCH_PERSPECTIVE}/titlesummary",
            params={
                "returnType": "default",
                "term": query,
                "offset": offset,
                "limit": limit,
                "searchScope": scope,
                "filterAvailableTitles": "false",
                "sort": "2910 desc",
                "clientMode": "BRANCH",
            },
            headers=self._headers(auth=True),
        )

        results = []
        for item in data.get("items", []):
            title_id = _extract_frbr_title_id(item)
            author_raw = item.get("author")
            author = (
                author_raw.get("description")
                if isinstance(author_raw, dict)
                else author_raw
            )
            media_raw = item.get("media")
            media = (
                media_raw.get("description")
                if isinstance(media_raw, dict)
                else media_raw
            )
            isbn_list = item.get("isbn") or []
            results.append(
                {
                    "title_id": title_id,
                    "title": item.get("title"),
                    "author": author,
                    "year": item.get("publicationYear"),
                    "media": media,
                    "isbn": isbn_list[0] if isbn_list else None,
                    "frbr_id": item.get("id"),
                }
            )

        return {"total": data.get("total", 0), "results": results}

    def check_availability(self, title_id: str) -> dict:
        """
        Check the availability of a title by its bibliographic record ID.

        Returns dict with 'available' (bool), 'hold_allowed' (bool),
        and a detailed 'availability' list from the server.
        """
        items = _api_json(
            "GET",
            f"{WISE_BASE}/branch/{self.branch_id}/titleavailability/{title_id}",
            params={"clientType": "PUBLIC"},
            headers=self._headers(),
        )

        if not items:
            return {
                "title_id": title_id,
                "available": False,
                "hold_allowed": False,
                "availability": [],
            }

        item = items[0]
        avail = item.get("availability", [])
        return {
            "title_id": title_id,
            "available": any(a.get("status") == "AVAILABLE" for a in avail),
            "hold_allowed": item.get("holdAllowed", False),
            "availability": avail,
        }

    def list_holds(self) -> list[dict]:
        """
        Return all active holds/reservations for the logged-in patron.

        Fetches both SEQUENTIAL and STANDARD reservation types and merges them.
        """
        self.ensure_logged_in()

        holds: list[dict] = []
        for reservation_type in ("STANDARD", "SEQUENTIAL"):
            data = _api_json(
                "GET",
                f"{WISE_BASE}/patron/{self._patron_id}"
                f"/library/{self.library_id}/hold",
                params={
                    "offset": 0,
                    "limit": 100,
                    "reservationType": reservation_type,
                },
                headers=self._headers(auth=True),
            )
            for item in data.get("items", []):
                holds.append(
                    {
                        "hold_id": item.get("id"),
                        "title": item.get("title"),
                        "author": item.get("author"),
                        "status": item.get("holdStatus"),
                        "queue_position": item.get("queuePosition"),
                        "awaiting_pickup": item.get("awaitingPickup"),
                        "pickup_location": item.get("pickupLocationName"),
                        "request_due_date": item.get("requestDueDate"),
                        "hold_placed_date": item.get("holdPlacedDate"),
                        "bibliographic_record_id": item.get("bibliographicRecordId"),
                        "reservation_type": reservation_type,
                    }
                )
        return holds

    def list_loans(self) -> list[dict]:
        """
        Return all items currently on loan for the logged-in patron.

        Each entry includes title, author, loan_date (when borrowed),
        due_date (return deadline), renewable flag, and branch name.
        """
        self.ensure_logged_in()

        data = _api_json(
            "GET",
            f"{WISE_BASE}/patron/{self._patron_id}/library/{self.library_id}/loan",
            params={"offset": 0},
            headers=self._headers(auth=True),
        )

        loans = []
        for item in data.get("items", []):
            loans.append(
                {
                    "loan_id": item.get("id"),
                    "title": item.get("title"),
                    "author": item.get("author"),
                    "loan_date": item.get("loanDate"),
                    "due_date": item.get("dueDate"),
                    "renewed_due_date": item.get("newDueDate"),
                    "renewable": item.get("itemRenewable", False),
                    "can_be_renewed": item.get("canBeRenewed", False),
                    "branch": item.get("loanBranchName"),
                    "media": item.get("medium"),
                    "fine": item.get("fine", 0.0),
                    "bibliographic_record_id": item.get("bibliographicRecordId"),
                }
            )
        return loans

    def place_hold(
        self,
        title_id: str,
        pickup_branch_id: str | None = None,
    ) -> dict:
        """
        Place a hold (reservation) for a title by its bibliographic record ID.

        The reservation window defaults to today + 28 days.
        pickup_branch_id defaults to the patron's home branch.
        """
        self.ensure_logged_in()

        pickup = pickup_branch_id or self.branch_id
        today = date.today()
        due_date = today + timedelta(days=28)

        payload = {
            "pickupBranchId": pickup,
            "requestStartDate": today.isoformat(),
            "requestDueDate": due_date.isoformat(),
            "holds": [
                {
                    "bibliographicRecordId": int(title_id),
                    "issueId": "",
                    "holdAllowed": True,
                    "fastDeliveryAllowed": False,
                    "reservationCostDetails": {
                        "placementCost": 0,
                        "pickupFee": 0,
                        "lendingFee": 0,
                        "punchCardPunches": 0,
                    },
                    "queuePosition": 0,
                    "illAllowed": False,
                }
            ],
            "holdType": "ALL",
            "pauseBeginDate": "",
            "pauseEndDate": "",
            "holdOptionsBranchId": pickup,
        }

        details = _api_json(
            "POST",
            f"{WISE_BASE}/patron/{self._patron_id}/hold",
            headers={
                **self._headers(auth=True),
                "Origin": "https://bibliotheek.wise.oclc.org",
            },
            body=payload,
        )
        return {"success": True, "details": details}
