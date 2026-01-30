from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional, Union
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx
import stripe
from bs4 import BeautifulSoup
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from sqlalchemy import Index, Integer, String, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

import firebase_admin
from firebase_admin import auth as fb_auth
from firebase_admin import credentials


# -----------------------------------------------------------------------------
# Settings
# -----------------------------------------------------------------------------
class Settings(BaseSettings):
    APP_NAME: str = "Saloon AI Agent"
    ENVIRONMENT: str = "dev"
    ALLOWED_ORIGINS: str = "http://localhost:5173"

    DATABASE_URL: str = "sqlite:///./app.db"

    # Supabase (storage only)
    SUPABASE_URL: str
    SUPABASE_SERVICE_ROLE_KEY: str
    SUPABASE_PROFILES_TABLE: str = "profiles"
    SUPABASE_SALON_PAYOUTS_TABLE: str = "salon_payouts"

    # Firebase Admin credentials
    FIREBASE_PROJECT_ID: str
    FIREBASE_CLIENT_EMAIL: str
    FIREBASE_PRIVATE_KEY: str

    # SerpApi
    SERPAPI_API_KEY: str
    SERPAPI_ENGINE: str = "google_maps"
    SERPAPI_GL: str = "nz"
    SERPAPI_HL: str = "en"
    SERP_CACHE_TTL_S: int = 600

    # Stripe
    STRIPE_SECRET_KEY: str
    STRIPE_WEBHOOK_SECRET: str
    STRIPE_SUCCESS_URL: str
    STRIPE_CANCEL_URL: str

    # Connect payout controls
    STRIPE_CONNECT_ENABLED: bool = False
    STRIPE_PLATFORM_FEE_PERCENT: int = 0  # 0-100

    # Safe fetch (SSRF)
    SAFE_FETCH_USER_AGENT: str = "SalonAgentBot/5.0"
    SAFE_FETCH_TIMEOUT_S: float = 10.0
    SAFE_FETCH_MAX_BYTES: int = 900_000
    SAFE_FETCH_ALLOW_PRIVATE_IPS: bool = False
    SAFE_FETCH_ALLOWED_PORTS: str = "80,443"
    SAFE_FETCH_MAX_REDIRECTS: int = 5

    # Booking scan
    BOOKING_SCAN_MAX_LINKS: int = 400
    BOOKING_SCAN_MAX_ANCHORS: int = 1500
    BOOKING_ONE_HOP_INTERNAL_CRAWL: bool = True
    BOOKING_WELL_KNOWN_PATHS: str = "/book,/booking,/appointments,/appointment,/contact,/services,/book-now"

    # Search limits
    DEFAULT_LIMIT: int = 10
    MAX_LIMIT: int = 30

    # Only show online booking salons
    REQUIRE_ONLINE_BOOKING: bool = True

    # Rate limiting + bans
    RL_IP_RPS: float = 1.2
    RL_USER_RPS: float = 1.2
    RL_BURST: int = 8

    # Tool budgets
    BUDGET_TOKENS_PER_REQUEST: int = 70
    COST_SERPAPI_SEARCH: int = 8
    COST_WEB_FETCH: int = 5
    COST_WEB_FETCH_ONE_HOP: int = 4
    MAX_WEBSITE_FETCHES: int = 14

    # Reputation lists
    DOMAIN_DENYLIST: str = "bit.ly,tinyurl.com,goo.gl,ow.ly"
    PROVIDER_DOMAINS: str = "timelyapp.com,timely.nz,fresha.com,square.site,squareup.com,booksy.com"

    class Config:
        env_file = ".env"
        extra = "ignore"

    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    def allowed_ports(self) -> set[int]:
        return {int(p.strip()) for p in self.SAFE_FETCH_ALLOWED_PORTS.split(",") if p.strip()}

    def deny_domains(self) -> set[str]:
        return {d.strip().lower() for d in self.DOMAIN_DENYLIST.split(",") if d.strip()}

    def provider_domains(self) -> set[str]:
        return {d.strip().lower() for d in self.PROVIDER_DOMAINS.split(",") if d.strip()}

    def booking_paths(self) -> list[str]:
        return [p.strip() for p in self.BOOKING_WELL_KNOWN_PATHS.split(",") if p.strip()]


settings = Settings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("backend")


def jlog(event: str, **fields: Any) -> str:
    return json.dumps({"event": event, **fields}, ensure_ascii=False, separators=(",", ":"))


stripe.api_key = settings.STRIPE_SECRET_KEY

if not firebase_admin._apps:
    private_key = settings.FIREBASE_PRIVATE_KEY.replace("\\n", "\n")
    cred = credentials.Certificate(
        {
            "type": "service_account",
            "project_id": settings.FIREBASE_PROJECT_ID,
            "client_email": settings.FIREBASE_CLIENT_EMAIL,
            "private_key": private_key,
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    )
    firebase_admin.initialize_app(cred)

NZ_NAMES = {"new zealand", "nz", "aotearoa", "aotearoa new zealand"}


# -----------------------------------------------------------------------------
# DB (only for caching / payment records)
# -----------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class SerpCache(Base):
    __tablename__ = "serp_cache"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(128), index=True, unique=True)
    response_json: Mapped[str] = mapped_column(String(350_000))
    created_at: Mapped[int] = mapped_column(Integer, default=lambda: int(time.time()), index=True)


class BookingPayment(Base):
    __tablename__ = "booking_payment"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    salon_key: Mapped[str] = mapped_column(String(64), index=True)
    stripe_session_id: Mapped[str] = mapped_column(String(128), index=True, unique=True)
    paid: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[int] = mapped_column(Integer, default=lambda: int(time.time()), index=True)


engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------------------------------------------------------------
# Middleware
# -----------------------------------------------------------------------------
@dataclass
class Bucket:
    tokens: float
    last: float


_RL_IP: dict[str, Bucket] = {}
_RL_USER: dict[str, Bucket] = {}


def _take_token(bucket_map: dict[str, Bucket], key: str, rps: float, burst: int) -> bool:
    now = time.time()
    b = bucket_map.get(key)
    if not b:
        bucket_map[key] = Bucket(tokens=float(burst - 1), last=now)
        return True
    elapsed = max(0.0, now - b.last)
    b.tokens = min(float(burst), b.tokens + elapsed * rps)
    b.last = now
    if b.tokens >= 1.0:
        b.tokens -= 1.0
        return True
    return False


class BanAndRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "unknown"

        if not _take_token(_RL_IP, ip, settings.RL_IP_RPS, settings.RL_BURST):
            return JSONResponse(status_code=429, content={"detail": "Rate limit (IP)"})

        authz = request.headers.get("authorization", "")
        if authz.startswith("Bearer "):
            token = authz.split(" ", 1)[1].strip()
            try:
                decoded = fb_auth.verify_id_token(token, check_revoked=False)
                uid = decoded.get("uid") or decoded.get("sub") or "unknown"
                if not _take_token(_RL_USER, uid, settings.RL_USER_RPS, settings.RL_BURST):
                    return JSONResponse(status_code=429, content={"detail": "Rate limit (user)"})
            except Exception:
                pass

        return await call_next(request)


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = rid
        resp: Response = await call_next(request)
        resp.headers["X-Request-Id"] = rid
        return resp


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except HTTPException:
            raise
        except Exception as e:
            rid = getattr(request.state, "request_id", None)
            log.exception(jlog("unhandled_error", request_id=rid, err=str(e)))
            return JSONResponse(status_code=500, content={"detail": "Internal server error", "request_id": rid})


# -----------------------------------------------------------------------------
# Auth (Firebase)
# -----------------------------------------------------------------------------
def get_current_user_id(authorization: str = Header(default="")) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        decoded = fb_auth.verify_id_token(token, check_revoked=False)
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid Firebase token") from e
    uid = decoded.get("user_id") or decoded.get("uid") or decoded.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token (missing uid)")
    return uid


# -----------------------------------------------------------------------------
# Supabase PostgREST (robust)
# -----------------------------------------------------------------------------
def _sanitize_header_value(v: str) -> str:
    v = (v or "").strip()
    v = "".join(ch for ch in v if 32 <= ord(ch) <= 126)
    return v


def _postgrest_base() -> str:
    return settings.SUPABASE_URL.strip().rstrip("/") + "/rest/v1"


def _supabase_headers() -> dict[str, str]:
    key = _sanitize_header_value(settings.SUPABASE_SERVICE_ROLE_KEY)
    if not key.startswith("eyJ"):
        raise HTTPException(status_code=500, detail="SUPABASE_SERVICE_ROLE_KEY invalid/malformed")
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "Connection": "close",
    }


def postgrest_get_single(table: str, select_cols: str, filters: dict[str, str]) -> dict[str, Any]:
    url = f"{_postgrest_base()}/{table}"
    params: dict[str, str] = {"select": select_cols}
    for k, v in filters.items():
        params[k] = f"eq.{v}"

    headers = _supabase_headers()
    timeout = httpx.Timeout(20.0, connect=8.0)

    last_err: Exception | None = None
    for attempt in range(1, 4):
        try:
            with httpx.Client(timeout=timeout, headers=headers, http2=False) as client:
                r = client.get(url, params=params)
                r.raise_for_status()
                data = r.json()
            if isinstance(data, list):
                return data[0] if data else {}
            if isinstance(data, dict):
                return data
            return {}
        except (httpx.LocalProtocolError, httpx.RemoteProtocolError, httpx.ReadError, httpx.ConnectError, httpx.ReadTimeout) as e:
            last_err = e
            time.sleep(0.5 * attempt)
            continue
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=502, detail=f"Supabase read failed: {e.response.status_code} - {e.response.text}") from e
        except Exception as e:
            last_err = e
            break
    raise HTTPException(status_code=502, detail=f"Supabase read failed: {type(last_err).__name__}")


def postgrest_patch(table: str, updates: dict[str, Any], filters: dict[str, str]) -> None:
    url = f"{_postgrest_base()}/{table}"
    params: dict[str, str] = {}
    for k, v in filters.items():
        params[k] = f"eq.{v}"
    headers = _supabase_headers()
    headers["Prefer"] = "return=minimal"
    timeout = httpx.Timeout(20.0, connect=8.0)

    last_err: Exception | None = None
    for attempt in range(1, 4):
        try:
            with httpx.Client(timeout=timeout, headers=headers, http2=False) as client:
                r = client.patch(url, params=params, json=updates)
                r.raise_for_status()
            return
        except (httpx.LocalProtocolError, httpx.RemoteProtocolError, httpx.ReadError, httpx.ConnectError, httpx.ReadTimeout) as e:
            last_err = e
            time.sleep(0.5 * attempt)
            continue
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=502, detail=f"Supabase update failed: {e.response.status_code} - {e.response.text}") from e
        except Exception as e:
            last_err = e
            break
    raise HTTPException(status_code=502, detail=f"Supabase update failed: {type(last_err).__name__}")


PROFILE_KEY_COL = "id"  # your firebase UID is stored in profiles.id


class UserLocation(BaseModel):
    city: Optional[str] = None
    suburb: Optional[str] = None
    postcode: Optional[Union[str, int]] = None
    country: Optional[str] = None


def fetch_user_location_and_country(user_id: str) -> UserLocation:
    row = postgrest_get_single(
        table=settings.SUPABASE_PROFILES_TABLE,
        select_cols="city,suburb,post_code,country",
        filters={PROFILE_KEY_COL: user_id},
    )
    return UserLocation(
        city=row.get("city"),
        suburb=row.get("suburb"),
        postcode=row.get("post_code"),
        country=row.get("country"),
    )


def get_salon_connect_account_id(salon_key: str) -> Optional[str]:
    row = postgrest_get_single(
        table=settings.SUPABASE_SALON_PAYOUTS_TABLE,
        select_cols="salon_key,stripe_account_id,active",
        filters={"salon_key": salon_key},
    )
    if not row:
        return None
    if row.get("active") is False:
        return None
    acct = row.get("stripe_account_id") or ""
    return acct if acct.startswith("acct_") else None


# -----------------------------------------------------------------------------
# Budget + helpers
# -----------------------------------------------------------------------------
@dataclass
class Budget:
    tokens_left: int
    website_fetches: int = 0

    def spend(self, amount: int):
        if self.tokens_left - amount < 0:
            raise HTTPException(status_code=429, detail="Request budget exceeded")
        self.tokens_left -= amount

    def can_fetch(self) -> bool:
        return self.website_fetches < settings.MAX_WEBSITE_FETCHES


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def salon_key_from_result(s: dict[str, Any]) -> str:
    payload = {
        "name": s.get("name") or s.get("title") or "",
        "website": s.get("website") or s.get("link") or "",
        "address": s.get("address") or s.get("formatted_address") or "",
        "phone": s.get("phone") or s.get("phone_number") or "",
    }
    return sha256(json.dumps(payload, sort_keys=True))


# -----------------------------------------------------------------------------
# SerpApi advanced search (multi-query + dedupe + score)
# -----------------------------------------------------------------------------
SERPAPI_ENDPOINT = "https://serpapi.com/search.json"


def serp_cache_key(q: str) -> str:
    return sha256(json.dumps({"engine": settings.SERPAPI_ENGINE, "q": q, "gl": settings.SERPAPI_GL, "hl": settings.SERPAPI_HL}, sort_keys=True))


def serp_call(query: str) -> list[dict[str, Any]]:
    params = {
        "api_key": settings.SERPAPI_API_KEY,
        "engine": settings.SERPAPI_ENGINE,
        "q": query,
        "gl": settings.SERPAPI_GL,
        "hl": settings.SERPAPI_HL,
    }
    headers = {"User-Agent": "SaloonAIAgent/1.0 (Render)", "Accept": "application/json", "Connection": "close"}
    timeout = httpx.Timeout(25.0, connect=10.0)

    last_err: Exception | None = None
    for attempt in range(1, 4):
        try:
            with httpx.Client(timeout=timeout, headers=headers, http2=False) as client:
                r = client.get(SERPAPI_ENDPOINT, params=params)
                r.raise_for_status()
                data = r.json()
            res = data.get("local_results") or data.get("place_results") or []
            return res if isinstance(res, list) else []
        except (httpx.RemoteProtocolError, httpx.ReadError, httpx.ConnectError, httpx.ReadTimeout) as e:
            last_err = e
            time.sleep(0.5 * attempt)
            continue
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=502, detail=f"SerpApi HTTP error: {e.response.status_code} - {e.response.text}") from e
    raise HTTPException(status_code=502, detail=f"SerpApi request failed: {type(last_err).__name__}")


def extract_booking_link_candidates(html: str, base_url: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html, "lxml")
    anchors = soup.find_all("a", limit=settings.BOOKING_SCAN_MAX_ANCHORS)
    out: list[tuple[str, str]] = []
    for a in anchors:
        href = a.get("href")
        if not href:
            continue
        href = href.strip()
        if href.startswith("#") or href.lower().startswith("javascript:"):
            continue
        full = urljoin(base_url, href)
        text = (a.get_text(" ", strip=True) or "")[:140]
        out.append((full, text))
    return out


DISALLOWED_SCHEMES = {"file", "ftp", "gopher", "ws", "wss", "data", "javascript"}
SUSPICIOUS_TLDS = (".local", ".internal", ".lan")
HOST_RE = re.compile(r"^[a-z0-9][a-z0-9\.\-]{0,252}[a-z0-9]$")

PROVIDER_RULES: dict[str, list[str]] = {
    "timely": ["timelyapp.com", "timely.nz"],
    "fresha": ["fresha.com"],
    "square": ["square.site", "squareup.com"],
    "booksy": ["booksy.com"],
}
BOOKING_KEYWORDS = ("book", "booking", "appointments", "appointment", "reserve", "reservation", "schedule")


def resolve_host_ips(hostname: str) -> list[str]:
    infos = socket.getaddrinfo(hostname, None)
    ips: set[str] = set()
    for family, _, _, _, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6):
            ips.add(str(sockaddr[0]))
    return sorted(ips)


def is_ip_private_or_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        return True


def looks_like_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable_domain(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    tld3 = ".".join(parts[-3:])
    if tld3.endswith(("co.nz", "org.nz", "ac.nz", "govt.nz", "net.nz", "iwi.nz")):
        return tld3
    return ".".join(parts[-2:])


def normalize_and_validate_url(url: str) -> str:
    if not url or not isinstance(url, str):
        raise ValueError("Empty URL")
    url = url.strip()
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse("https://" + url)

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or scheme in DISALLOWED_SCHEMES:
        raise ValueError("Disallowed scheme")
    if parsed.username or parsed.password:
        raise ValueError("Userinfo not allowed")

    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError("Missing hostname")
    if host.endswith(SUSPICIOUS_TLDS):
        raise ValueError("Suspicious TLD")
    if host in settings.deny_domains() or registrable_domain(host) in settings.deny_domains():
        raise ValueError("Denylisted domain")
    if looks_like_ip_host(host):
        raise ValueError("Direct IP host not allowed")
    if not HOST_RE.fullmatch(host):
        raise ValueError("Invalid hostname")

    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    if port not in settings.allowed_ports():
        raise ValueError("Port not allowed")

    if not settings.SAFE_FETCH_ALLOW_PRIVATE_IPS:
        for ip in resolve_host_ips(host):
            if is_ip_private_or_local(ip):
                raise ValueError("Resolves to private/local IP")

    return urlunparse((scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def detect_provider(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    for provider, domains in PROVIDER_RULES.items():
        for d in domains:
            if host == d or host.endswith("." + d):
                return provider
    return "other"


def strip_tracking_params(url: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for k in list(q.keys()):
        lk = k.lower()
        if lk.startswith("utm_") or lk in {"gclid", "fbclid", "mc_cid", "mc_eid"}:
            q.pop(k, None)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(q, doseq=True), ""))


def booking_confidence(url: str, anchor_text: str = "") -> int:
    prov = detect_provider(url)
    score = 0
    if prov != "other":
        score += 70
    if any(k in url.lower() for k in BOOKING_KEYWORDS):
        score += 20
    if anchor_text and any(k in anchor_text.lower() for k in ("book", "booking", "appointment", "reserve")):
        score += 10
    return max(0, min(100, score))


def safe_fetch_html(url: str, budget: Budget) -> str:
    budget.spend(settings.COST_WEB_FETCH)
    budget.website_fetches += 1

    url = normalize_and_validate_url(url)
    headers = {"User-Agent": settings.SAFE_FETCH_USER_AGENT, "Accept": "text/html,*/*", "Connection": "close"}
    timeout = httpx.Timeout(settings.SAFE_FETCH_TIMEOUT_S, connect=5.0)

    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True, http2=False) as client:
        r = client.get(url)
        r.raise_for_status()
        ctype = (r.headers.get("content-type") or "").lower()
        if "text/html" not in ctype and "application/xhtml" not in ctype:
            raise ValueError("Not HTML")
        content = r.content
        if len(content) > settings.SAFE_FETCH_MAX_BYTES:
            raise ValueError("Response too large")
        return content.decode(r.encoding or "utf-8", errors="replace")


def extract_booking_url_from_website(website: Optional[str], budget: Budget) -> tuple[Optional[str], str, int]:
    if not website:
        return None, "none", 0
    try:
        website = normalize_and_validate_url(website)
    except Exception:
        return None, "none", 0

    prov = detect_provider(website)
    if prov != "other":
        return website, prov, booking_confidence(website)

    if not budget.can_fetch():
        return None, "none", 0

    try:
        html = safe_fetch_html(website, budget)
        candidates = extract_booking_link_candidates(html, website)
        best_url = None
        best_score = 0
        for u, t in candidates[: settings.BOOKING_SCAN_MAX_LINKS]:
            try:
                uu = normalize_and_validate_url(u)
                uu = strip_tracking_params(uu)
            except Exception:
                continue
            score = booking_confidence(uu, anchor_text=t)
            if score > best_score:
                best_score = score
                best_url = uu
        if best_url:
            return best_url, detect_provider(best_url), best_score

        # one-hop internal guesses
        if settings.BOOKING_ONE_HOP_INTERNAL_CRAWL and budget.can_fetch():
            parsed = urlparse(website)
            base = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
            for p in settings.booking_paths():
                if not budget.can_fetch():
                    break
                guess = urljoin(base, p.lstrip("/"))
                budget.spend(settings.COST_WEB_FETCH_ONE_HOP)
                budget.website_fetches += 1
                try:
                    html2 = safe_fetch_html(guess, budget)
                except Exception:
                    continue
                candidates2 = extract_booking_link_candidates(html2, guess)
                for u, t in candidates2[: settings.BOOKING_SCAN_MAX_LINKS]:
                    try:
                        uu = normalize_and_validate_url(u)
                        uu = strip_tracking_params(uu)
                    except Exception:
                        continue
                    score = booking_confidence(uu, anchor_text=t)
                    if score > best_score:
                        best_score = score
                        best_url = uu
                if best_url:
                    return best_url, detect_provider(best_url), best_score

        return None, "none", 0
    except Exception:
        return None, "none", 0


def looks_like_online_booking(booking_url: Optional[str], provider: str, confidence: int) -> bool:
    if not booking_url:
        return False
    if provider != "none" and provider != "other":
        return True
    return confidence >= 70


# -----------------------------------------------------------------------------
# Advanced search endpoint models
# -----------------------------------------------------------------------------
class SalonSearchRequest(BaseModel):
    query: Optional[str] = Field(default=None, max_length=80)
    limit: int = Field(default=10, ge=1, le=30)


class SalonResult(BaseModel):
    salon_key: str
    name: str
    address: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    rating: Optional[float] = None
    reviews: Optional[int] = None

    booking_url: Optional[str] = None
    booking_provider: str = "none"
    booking_confidence: int = 0

    connect_supported: bool = False


class SalonSearchResponse(BaseModel):
    salons: list[SalonResult]
    meta: dict[str, Any] = {}


class StartSalonPaymentRequest(BaseModel):
    salon_key: str
    amount_cents: int = Field(ge=50)  # minimum 50 cents
    currency: str = "nzd"


class StartSalonPaymentResponse(BaseModel):
    checkout_url: str
    stripe_session_id: str


# -----------------------------------------------------------------------------
# FastAPI app
# -----------------------------------------------------------------------------
app = FastAPI(title=settings.APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(BanAndRateLimitMiddleware)
app.add_middleware(ErrorHandlerMiddleware)


@app.on_event("startup")
def startup():
    init_db()
    log.info(jlog("startup", allowed_origins=settings.allowed_origins_list()))


@app.get("/")
def root():
    return {"ok": True, "service": "backend", "allowed_origins": settings.allowed_origins_list()}


@app.get("/api/v1/health")
def health():
    return {"ok": True}


@app.post("/api/v1/salons/search", response_model=SalonSearchResponse)
def salons_search(
    req: SalonSearchRequest,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    rid = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    limit = max(1, min(int(req.limit), settings.MAX_LIMIT))
    budget = Budget(tokens_left=settings.BUDGET_TOKENS_PER_REQUEST)

    loc = fetch_user_location_and_country(user_id)
    if not loc.country or str(loc.country).strip().lower() not in NZ_NAMES:
        raise HTTPException(status_code=400, detail="Country must be New Zealand")

    base_terms = [loc.suburb, loc.city, str(loc.postcode or ""), "New Zealand"]
    base = " ".join([t for t in base_terms if t and str(t).strip()])

    user_query = (req.query or "hair salon").strip()

    queries = [
        f"{user_query} {base} book online",
        f"{user_query} {base} online booking",
        f"hair salon {base} book online",
        f"barber {base} online booking",
    ]

    # Fetch and merge
    merged: dict[str, dict[str, Any]] = {}
    for q in queries:
        results = serp_call(q)
        for r in results:
            sk = salon_key_from_result(r)
            if sk not in merged:
                merged[sk] = r

    salons: list[SalonResult] = []
    for sk, r in merged.items():
        name = r.get("title") or r.get("name") or "Unknown"
        website = r.get("website") or r.get("link")
        rating = r.get("rating")
        reviews = r.get("reviews") or r.get("reviews_count")

        booking_url, provider, conf = extract_booking_url_from_website(website, budget=budget)

        if settings.REQUIRE_ONLINE_BOOKING and not looks_like_online_booking(booking_url, provider, conf):
            continue

        acct = get_salon_connect_account_id(sk) if settings.STRIPE_CONNECT_ENABLED else None

        salons.append(
            SalonResult(
                salon_key=sk,
                name=name,
                address=r.get("address") or r.get("formatted_address"),
                phone=r.get("phone") or r.get("phone_number"),
                website=website,
                rating=float(rating) if rating is not None else None,
                reviews=int(reviews) if reviews is not None else None,
                booking_url=booking_url,
                booking_provider=provider,
                booking_confidence=conf,
                connect_supported=bool(acct),
            )
        )

    # Ranking: booking confidence, rating, reviews
    salons.sort(key=lambda s: (-(s.booking_confidence or 0), -(s.rating or 0.0), -(s.reviews or 0)))

    return SalonSearchResponse(
        salons=salons[:limit],
        meta={
            "request_id": rid,
            "tokens_left": budget.tokens_left,
            "website_fetches": budget.website_fetches,
            "require_online_booking": settings.REQUIRE_ONLINE_BOOKING,
        },
    )


@app.post("/api/v1/payments/start-salon-payment", response_model=StartSalonPaymentResponse)
def start_salon_payment(
    req: StartSalonPaymentRequest,
    user_id: str = Depends(get_current_user_id),
):
    """
    Stripe Connect payment to the salon.
    Requires:
      - STRIPE_CONNECT_ENABLED=true
      - salon_payouts table row exists for salon_key with stripe_account_id=acct_... and active=true
    """
    if not settings.STRIPE_CONNECT_ENABLED:
        raise HTTPException(status_code=400, detail="Stripe Connect is not enabled")

    acct = get_salon_connect_account_id(req.salon_key)
    if not acct:
        raise HTTPException(status_code=400, detail="This salon is not enabled for in-app payment yet")

    if req.currency.lower() != "nzd":
        raise HTTPException(status_code=400, detail="Only NZD supported for now")

    # Platform fee (optional)
    fee = int(req.amount_cents * (settings.STRIPE_PLATFORM_FEE_PERCENT / 100.0))

    session = stripe.checkout.Session.create(
        mode="payment",
        success_url=settings.STRIPE_SUCCESS_URL,
        cancel_url=settings.STRIPE_CANCEL_URL,
        line_items=[
            {
                "price_data": {
                    "currency": "nzd",
                    "product_data": {"name": "Salon booking payment"},
                    "unit_amount": req.amount_cents,
                },
                "quantity": 1,
            }
        ],
        payment_intent_data={
            "application_fee_amount": fee if fee > 0 else None,
            "transfer_data": {"destination": acct},
        },
        metadata={"purpose": "salon_payment", "user_id": user_id, "salon_key": req.salon_key},
    )

    return StartSalonPaymentResponse(checkout_url=session.url, stripe_session_id=session.id)