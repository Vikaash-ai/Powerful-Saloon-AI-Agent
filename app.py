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

from supabase import create_client


# -----------------------------------------------------------------------------
# Settings (NO hardcoded secrets here)
# -----------------------------------------------------------------------------
class Settings(BaseSettings):
    APP_NAME: str = "Saloon AI Agent"
    ENVIRONMENT: str = "dev"

    # IMPORTANT: must match your frontend dev origin
    # For Vite: http://localhost:5173
    ALLOWED_ORIGINS: str = "http://localhost:5173"

    DATABASE_URL: str = "sqlite:///./app.db"

    # Supabase (storage only)
    SUPABASE_URL: str
    SUPABASE_SERVICE_ROLE_KEY: str
    SUPABASE_PROFILES_TABLE: str = "profiles"
    SUPABASE_CONSUME_CREDIT_RPC: str = "consume_credit"

    # Firebase Admin credentials
    FIREBASE_PROJECT_ID: str
    FIREBASE_CLIENT_EMAIL: str
    FIREBASE_PRIVATE_KEY: str  # store with \n in env; we convert.

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
    STRIPE_BOOKING_FEE_PRICE_ID: str

    # Safe fetch (SSRF)
    SAFE_FETCH_USER_AGENT: str = "SalonAgentBot/4.0"
    SAFE_FETCH_TIMEOUT_S: float = 8.0
    SAFE_FETCH_MAX_BYTES: int = 900_000
    SAFE_FETCH_ALLOW_PRIVATE_IPS: bool = False
    SAFE_FETCH_ALLOWED_PORTS: str = "80,443"
    SAFE_FETCH_MAX_REDIRECTS: int = 5

    # Booking scan
    BOOKING_SCAN_MAX_LINKS: int = 300
    BOOKING_SCAN_MAX_ANCHORS: int = 1200
    BOOKING_ONE_HOP_INTERNAL_CRAWL: bool = True
    BOOKING_WELL_KNOWN_PATHS: str = "/book,/booking,/appointments,/appointment,/contact,/services"

    # Search limits
    DEFAULT_LIMIT: int = 10
    MAX_LIMIT: int = 30

    # Rate limiting + bans
    RL_IP_RPS: float = 1.2
    RL_USER_RPS: float = 1.2
    RL_BURST: int = 8
    BAN_WINDOW_S: int = 600
    BAN_THRESHOLD: int = 5
    BAN_THRESHOLD_HARD: int = 10
    BAN_KIND_WEIGHTS: str = "ssrf_block=3,invalid_url=2,ratelimit=1,fetch_fail=1,webhook_fail=2"

    # Tool budgets
    BUDGET_TOKENS_PER_REQUEST: int = 55
    COST_SERPAPI_SEARCH: int = 8
    COST_WEB_FETCH: int = 5
    COST_WEB_FETCH_ONE_HOP: int = 4
    MAX_WEBSITE_FETCHES: int = 12

    # Idempotency TTL
    IDEM_TTL_S: int = 240

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

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("backend")


def jlog(event: str, **fields: Any) -> str:
    return json.dumps({"event": event, **fields}, ensure_ascii=False, separators=(",", ":"))


# Stripe init
stripe.api_key = settings.STRIPE_SECRET_KEY

# Firebase Admin init
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
# DB
# -----------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class IdempotencyCache(Base):
    __tablename__ = "idempotency_cache"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    key: Mapped[str] = mapped_column(String(128), index=True)
    path: Mapped[str] = mapped_column(String(128), index=True)
    body_hash: Mapped[str] = mapped_column(String(64), index=True)
    response_json: Mapped[str] = mapped_column(String(220_000))
    created_at: Mapped[int] = mapped_column(Integer, default=lambda: int(time.time()), index=True)


Index("ix_idem_unique", IdempotencyCache.user_id, IdempotencyCache.key, IdempotencyCache.path, IdempotencyCache.body_hash, unique=True)


class SecurityEvent(Base):
    __tablename__ = "security_event"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(160), index=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[int] = mapped_column(Integer, default=lambda: int(time.time()), index=True)


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
# Middleware (rate limit/bans)
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


def _ban_weights() -> dict[str, int]:
    out: dict[str, int] = {}
    for pair in settings.BAN_KIND_WEIGHTS.split(","):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        out[k.strip()] = int(v.strip())
    return out


BAN_WEIGHTS = _ban_weights()


def security_event(db: Session, key: str, kind: str) -> None:
    db.add(SecurityEvent(key=key, kind=kind))
    db.commit()


def ban_score(db: Session, key: str) -> int:
    cutoff = int(time.time()) - settings.BAN_WINDOW_S
    rows = db.execute(select(SecurityEvent.kind).where(SecurityEvent.key == key, SecurityEvent.created_at >= cutoff)).all()
    score = 0
    for (kind,) in rows:
        score += BAN_WEIGHTS.get(kind, 1)
    return score


class BanAndRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "unknown"

        with SessionLocal() as db:
            score = ban_score(db, f"ip:{ip}")
            if score >= settings.BAN_THRESHOLD_HARD:
                return JSONResponse(status_code=403, content={"detail": "Blocked (hard)"})
            if score >= settings.BAN_THRESHOLD:
                return JSONResponse(status_code=403, content={"detail": "Temporarily blocked"})

        if not _take_token(_RL_IP, ip, settings.RL_IP_RPS, settings.RL_BURST):
            with SessionLocal() as db:
                security_event(db, f"ip:{ip}", "ratelimit")
            return JSONResponse(status_code=429, content={"detail": "Rate limit (IP)"})

        authz = request.headers.get("authorization", "")
        if authz.startswith("Bearer "):
            token = authz.split(" ", 1)[1].strip()
            try:
                decoded = fb_auth.verify_id_token(token, check_revoked=False)
                uid = decoded.get("uid") or decoded.get("sub") or "unknown"
                if not _take_token(_RL_USER, uid, settings.RL_USER_RPS, settings.RL_BURST):
                    with SessionLocal() as db:
                        security_event(db, f"user:{uid}", "ratelimit")
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
def verify_firebase_token(token: str) -> dict[str, Any]:
    try:
        return fb_auth.verify_id_token(token, check_revoked=False)
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid Firebase token") from e


def get_current_user_id(authorization: str = Header(default="")) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    decoded = verify_firebase_token(token)
    uid = decoded.get("uid") or decoded.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token (missing uid)")
    return uid


# -----------------------------------------------------------------------------
# Supabase admin (storage only)
# -----------------------------------------------------------------------------
def supabase_admin():
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)


class UserLocation(BaseModel):
    city: Optional[str] = None
    suburb: Optional[str] = None
    postcode: Optional[Union[str, int]] = None
    country: Optional[str] = None


def get_user_credit(user_id: str) -> int:
    sb = supabase_admin()
    resp = sb.table(settings.SUPABASE_PROFILES_TABLE).select("credit").eq("id", user_id).single().execute()
    return int((resp.data or {}).get("credit") or 0)


def consume_credit_atomic(user_id: str, amount: int = 1) -> int:
    sb = supabase_admin()
    rpc = (settings.SUPABASE_CONSUME_CREDIT_RPC or "").strip()

    if rpc:
        try:
            res = sb.rpc(rpc, {"p_user_id": user_id, "p_amount": amount}).execute()
            data = res.data
            if isinstance(data, dict) and "credit" in data:
                return int(data["credit"])
            if isinstance(data, list) and data and isinstance(data[0], dict) and "credit" in data[0]:
                return int(data[0]["credit"])
        except Exception:
            pass

    current = get_user_credit(user_id)
    if current < amount:
        raise HTTPException(status_code=402, detail="Not enough credits")
    new_val = current - amount
    sb.table(settings.SUPABASE_PROFILES_TABLE).update({"credit": new_val}).eq("id", user_id).execute()
    return new_val


def fetch_user_location_and_country(user_id: str) -> UserLocation:
    sb = supabase_admin()
    resp = (
        sb.table(settings.SUPABASE_PROFILES_TABLE)
        .select("city,suburb,postcode,country")
        .eq("id", user_id)
        .single()
        .execute()
    )
    data = resp.data or {}
    return UserLocation(
        city=data.get("city"),
        suburb=data.get("suburb"),
        postcode=data.get("postcode"),
        country=data.get("country"),
    )


# -----------------------------------------------------------------------------
# Tool budget + helpers
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


# -----------------------------------------------------------------------------
# SerpApi
# -----------------------------------------------------------------------------
SERPAPI_ENDPOINT = "https://serpapi.com/search.json"


def serp_cache_key(q: str) -> str:
    return sha256(json.dumps({"engine": settings.SERPAPI_ENGINE, "q": q, "gl": settings.SERPAPI_GL, "hl": settings.SERPAPI_HL}, sort_keys=True))


def serp_search_local(db: Session, query: str, budget: Budget, request_id: str) -> list[dict[str, Any]]:
    cutoff = int(time.time()) - settings.SERP_CACHE_TTL_S
    key = serp_cache_key(query)

    cached = db.execute(select(SerpCache).where(SerpCache.key == key, SerpCache.created_at >= cutoff)).scalar_one_or_none()
    if cached:
        return json.loads(cached.response_json)

    budget.spend(settings.COST_SERPAPI_SEARCH)
    params = {
        "api_key": settings.SERPAPI_API_KEY,
        "engine": settings.SERPAPI_ENGINE,
        "q": query,
        "gl": settings.SERPAPI_GL,
        "hl": settings.SERPAPI_HL,
    }

    timeout = httpx.Timeout(18.0, connect=5.0)
    with httpx.Client(timeout=timeout) as client:
        r = client.get(SERPAPI_ENDPOINT, params=params)
        r.raise_for_status()
        data = r.json()

    local_results = data.get("local_results") or data.get("place_results") or []
    if not isinstance(local_results, list):
        local_results = []

    db.add(SerpCache(key=key, response_json=json.dumps(local_results, ensure_ascii=False)))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()

    return local_results


# -----------------------------------------------------------------------------
# SSRF-hardened fetch + booking extraction (same logic you already had)
# -----------------------------------------------------------------------------
DISALLOWED_SCHEMES = {"file", "ftp", "gopher", "ws", "wss", "data", "javascript"}
SUSPICIOUS_TLDS = (".local", ".internal", ".lan")
HOST_RE = re.compile(r"^[a-z0-9][a-z0-9\.\-]{0,252}[a-z0-9]$")


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


def safe_fetch_html(url: str, request_id: str, budget: Budget) -> str:
    budget.spend(settings.COST_WEB_FETCH)
    budget.website_fetches += 1
    url = normalize_and_validate_url(url)

    headers = {"User-Agent": settings.SAFE_FETCH_USER_AGENT, "Accept": "text/html,*/*"}
    timeout = httpx.Timeout(settings.SAFE_FETCH_TIMEOUT_S, connect=5.0)

    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
        r = client.get(url)
        r.raise_for_status()
        ctype = (r.headers.get("content-type") or "").lower()
        if "text/html" not in ctype and "application/xhtml" not in ctype:
            raise ValueError("Not HTML")
        content = r.content
        if len(content) > settings.SAFE_FETCH_MAX_BYTES:
            raise ValueError("Response too large")
        return content.decode(r.encoding or "utf-8", errors="replace")


PROVIDER_RULES: dict[str, list[str]] = {
    "timely": ["timelyapp.com", "timely.nz"],
    "fresha": ["fresha.com"],
    "square": ["square.site", "squareup.com"],
    "booksy": ["booksy.com"],
}
BOOKING_KEYWORDS = ("book", "booking", "appointments", "appointment", "reserve", "reservation", "schedule")


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
    score = 10
    if prov != "other":
        score += 60
    if any(k in url.lower() for k in BOOKING_KEYWORDS):
        score += 20
    if anchor_text and any(k in anchor_text.lower() for k in ("book", "booking", "appointment", "reserve")):
        score += 10
    return max(0, min(100, score))


def booking_link_allowed(salon_website: str, booking_url: str) -> bool:
    b = normalize_and_validate_url(booking_url)
    s = normalize_and_validate_url(salon_website)
    if detect_provider(b) != "other":
        return True
    bh = (urlparse(b).hostname or "").lower()
    sh = (urlparse(s).hostname or "").lower()
    return registrable_domain(bh) == registrable_domain(sh)


def extract_booking_url_from_website(
    salon_website: Optional[str],
    request_id: str,
    budget: Budget,
) -> tuple[Optional[str], str, int, dict[str, Any]]:
    if not salon_website:
        return None, "none", 0, {}

    try:
        website = normalize_and_validate_url(salon_website)
    except Exception:
        return None, "none", 0, {}

    prov = detect_provider(website)
    if prov != "other":
        return website, prov, booking_confidence(website), {"source": "website_is_provider"}

    if not budget.can_fetch():
        return None, "none", 0, {"source": "budget_no_fetch"}

    try:
        html = safe_fetch_html(website, request_id, budget)
        soup = BeautifulSoup(html, "lxml")
        anchors = soup.find_all("a", limit=settings.BOOKING_SCAN_MAX_ANCHORS)

        candidates: list[tuple[str, str]] = []
        for a in anchors:
            href = a.get("href")
            if not href:
                continue
            href = href.strip()
            if href.startswith("#") or href.lower().startswith("javascript:"):
                continue
            full = urljoin(website, href)
            text = (a.get_text(" ", strip=True) or "")[:120]
            candidates.append((full, text))

        best_url = None
        best_score = 0
        evidence: dict[str, Any] = {}
        seen: set[str] = set()

        for url, text in candidates[: settings.BOOKING_SCAN_MAX_LINKS]:
            try:
                u = normalize_and_validate_url(url)
                u = strip_tracking_params(u)
            except Exception:
                continue
            if u in seen:
                continue
            seen.add(u)

            sc = booking_confidence(u, anchor_text=text)
            if sc > best_score and booking_link_allowed(website, u):
                best_url = u
                best_score = sc
                evidence = {"anchor_text": text, "source": "homepage_scan"}

        if best_url:
            return best_url, detect_provider(best_url), best_score, evidence

        # one-hop well-known paths (optional)
        if settings.BOOKING_ONE_HOP_INTERNAL_CRAWL and budget.can_fetch():
            parsed = urlparse(website)
            base = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
            for p in settings.booking_paths():
                if not budget.can_fetch():
                    break
                guess = urljoin(base, p.lstrip("/"))
                # cheap one-hop cost
                budget.spend(settings.COST_WEB_FETCH_ONE_HOP)
                budget.website_fetches += 1
                try:
                    html2 = safe_fetch_html(guess, request_id, budget)
                except Exception:
                    continue
                soup2 = BeautifulSoup(html2, "lxml")
                anchors2 = soup2.find_all("a", limit=settings.BOOKING_SCAN_MAX_ANCHORS)
                candidates2: list[tuple[str, str]] = []
                for a in anchors2:
                    href = a.get("href")
                    if not href:
                        continue
                    full = urljoin(guess, href.strip())
                    text = (a.get_text(" ", strip=True) or "")[:120]
                    candidates2.append((full, text))

                for url, text in candidates2[: settings.BOOKING_SCAN_MAX_LINKS]:
                    try:
                        u = normalize_and_validate_url(url)
                        u = strip_tracking_params(u)
                    except Exception:
                        continue
                    sc = booking_confidence(u, anchor_text=text)
                    if sc > best_score and booking_link_allowed(website, u):
                        best_url = u
                        best_score = sc
                        evidence = {"anchor_text": text, "source": "well_known_path", "page": guess}
                        break

                if best_url:
                    return best_url, detect_provider(best_url), best_score, evidence

        return None, "none", 0, {"source": "no_booking_found"}
    except Exception:
        return None, "none", 0, {"source": "fetch_failed"}


# -----------------------------------------------------------------------------
# Stripe checkout helpers
# -----------------------------------------------------------------------------
def salon_key(salon: dict[str, Any]) -> str:
    payload = {
        "name": salon.get("name") or "",
        "website": salon.get("website") or "",
        "address": salon.get("address") or "",
        "phone": salon.get("phone") or "",
    }
    return sha256(json.dumps(payload, sort_keys=True))


def create_booking_fee_checkout_session(user_id: str, salon: dict[str, Any]) -> stripe.checkout.Session:
    skey = salon_key(salon)
    return stripe.checkout.Session.create(
        mode="payment",
        success_url=settings.STRIPE_SUCCESS_URL,
        cancel_url=settings.STRIPE_CANCEL_URL,
        line_items=[{"price": settings.STRIPE_BOOKING_FEE_PRICE_ID, "quantity": 1}],
        metadata={"purpose": "booking_fee", "user_id": user_id, "salon_key": skey},
    )


# -----------------------------------------------------------------------------
# Idempotency helpers
# -----------------------------------------------------------------------------
def idem_hash(payload: dict[str, Any], user_id: str) -> str:
    return sha256(json.dumps({"user": user_id, "payload": payload}, sort_keys=True))


def idem_get(db: Session, user_id: str, key: str, path: str, body_hash: str) -> Optional[dict[str, Any]]:
    cutoff = int(time.time()) - settings.IDEM_TTL_S
    row = db.execute(
        select(IdempotencyCache).where(
            IdempotencyCache.user_id == user_id,
            IdempotencyCache.key == key,
            IdempotencyCache.path == path,
            IdempotencyCache.body_hash == body_hash,
            IdempotencyCache.created_at >= cutoff,
        )
    ).scalar_one_or_none()
    if not row:
        return None
    return json.loads(row.response_json)


def idem_put(db: Session, user_id: str, key: str, path: str, body_hash: str, payload: dict[str, Any]) -> None:
    db.add(
        IdempotencyCache(
            user_id=user_id,
            key=key,
            path=path,
            body_hash=body_hash,
            response_json=json.dumps(payload, ensure_ascii=False),
        )
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()


# -----------------------------------------------------------------------------
# API models
# -----------------------------------------------------------------------------
class SalonSearchRequest(BaseModel):
    query: Optional[str] = Field(default=None, max_length=80)
    limit: int = Field(default=10, ge=1, le=30)
    location_override: Optional[UserLocation] = None


class SalonResult(BaseModel):
    name: str
    address: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    rating: Optional[float] = None
    reviews: Optional[int] = None


class SalonSearchResponse(BaseModel):
    salons: list[SalonResult]
    meta: dict[str, Any] = {}


class StartBookingPaymentRequest(BaseModel):
    salon: dict[str, Any]


class StartBookingPaymentResponse(BaseModel):
    checkout_url: str
    stripe_session_id: str


class RevealBookingRequest(BaseModel):
    salon: dict[str, Any]
    stripe_session_id: str


class RevealBookingResponse(BaseModel):
    booking_url: Optional[str] = None
    booking_provider: str = "none"
    booking_confidence: int = 0
    evidence: dict[str, Any] = {}
    credits_left: Optional[int] = None


# -----------------------------------------------------------------------------
# FastAPI app (CORS FIXED via env var)
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
    log.info(jlog("startup", env=settings.ENVIRONMENT, db=settings.DATABASE_URL, allowed_origins=settings.allowed_origins_list()))


@app.get("/")
def root():
    return {
        "ok": True,
        "service": "backend",
        "allowed_origins": settings.allowed_origins_list(),
        "hint": "Try /docs, /api/v1/health",
    }


@app.get("/api/v1/health")
def health():
    return {"ok": True}


@app.post("/api/v1/salons/search", response_model=SalonSearchResponse)
def salons_search(
    req: SalonSearchRequest,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    rid = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    limit = max(1, min(int(req.limit), settings.MAX_LIMIT))
    budget = Budget(tokens_left=settings.BUDGET_TOKENS_PER_REQUEST)

    payload = req.model_dump()
    body_hash = idem_hash(payload, user_id)
    if idempotency_key:
        cached = idem_get(db, user_id, idempotency_key, str(request.url.path), body_hash)
        if cached:
            return cached

    loc = req.location_override or fetch_user_location_and_country(user_id)
    if not loc.country or str(loc.country).strip().lower() not in NZ_NAMES:
        raise HTTPException(status_code=400, detail="Country must be New Zealand")

    pieces = [req.query or "hair salon", loc.suburb, loc.city, loc.postcode, "New Zealand"]
    q = " ".join([str(p).strip() for p in pieces if p and str(p).strip()])

    results = serp_search_local(db=db, query=q, budget=budget, request_id=rid)

    salons: list[SalonResult] = []
    for item in results[: max(limit * 3, limit)]:
        salons.append(
            SalonResult(
                name=item.get("title") or item.get("name") or "Unknown",
                address=item.get("address") or item.get("formatted_address"),
                phone=item.get("phone") or item.get("phone_number"),
                website=item.get("website") or item.get("link"),
                rating=float(item.get("rating")) if item.get("rating") is not None else None,
                reviews=int(item.get("reviews") or item.get("reviews_count")) if (item.get("reviews") or item.get("reviews_count")) is not None else None,
            )
        )

    salons.sort(key=lambda s: (-(s.rating or 0.0), -(s.reviews or 0)))
    resp = SalonSearchResponse(salons=salons[:limit], meta={"query_used": q, "request_id": rid}).model_dump()

    if idempotency_key:
        idem_put(db, user_id, idempotency_key, str(request.url.path), body_hash, resp)

    return resp


@app.post("/api/v1/booking/start-payment", response_model=StartBookingPaymentResponse)
def start_booking_payment(req: StartBookingPaymentRequest, user_id: str = Depends(get_current_user_id)):
    session = create_booking_fee_checkout_session(user_id=user_id, salon=req.salon)
    if not session.url:
        raise HTTPException(status_code=500, detail="Stripe session URL is missing")
    return StartBookingPaymentResponse(checkout_url=session.url, stripe_session_id=session.id)


@app.post("/api/v1/booking/reveal", response_model=RevealBookingResponse)
def reveal_booking(
    req: RevealBookingRequest,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    rid = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    skey = salon_key(req.salon)

    row = db.execute(
        select(BookingPayment).where(
            BookingPayment.user_id == user_id,
            BookingPayment.salon_key == skey,
            BookingPayment.stripe_session_id == req.stripe_session_id,
            BookingPayment.paid == 1,
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=403, detail="Payment not verified yet")

    budget = Budget(tokens_left=settings.BUDGET_TOKENS_PER_REQUEST)
    booking_url, provider, conf, evidence = extract_booking_url_from_website(
        salon_website=req.salon.get("website"),
        request_id=rid,
        budget=budget,
    )

    return RevealBookingResponse(
        booking_url=booking_url,
        booking_provider=provider,
        booking_confidence=conf,
        evidence=evidence,
        credits_left=get_user_credit(user_id),
    )


@app.post("/api/v1/stripe/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig, secret=settings.STRIPE_WEBHOOK_SECRET)
    except Exception:
        security_event(db, "webhook", "webhook_fail")
        return JSONResponse(status_code=400, content={"detail": "Invalid webhook signature"})

    if event["type"] != "checkout.session.completed":
        return {"ok": True}

    session = event["data"]["object"]
    metadata = session.get("metadata") or {}
    if metadata.get("purpose") != "booking_fee":
        return {"ok": True}

    user_id = metadata.get("user_id")
    skey = metadata.get("salon_key")
    session_id = session.get("id")

    if not user_id or not skey or not session_id:
        return JSONResponse(status_code=400, content={"detail": "Missing metadata"})

    existing = db.execute(select(BookingPayment).where(BookingPayment.stripe_session_id == session_id)).scalar_one_or_none()
    if existing:
        return {"ok": True}

    try:
        remaining = consume_credit_atomic(user_id=user_id, amount=1)
    except HTTPException:
        return JSONResponse(status_code=409, content={"detail": "Paid but no credits available"})

    db.add(BookingPayment(user_id=user_id, salon_key=skey, stripe_session_id=session_id, paid=1))
    db.commit()

    log.info(jlog("stripe_booking_fee_paid", user_id=user_id, salon_key=skey, session_id=session_id, credits_left=remaining))
    return {"ok": True}