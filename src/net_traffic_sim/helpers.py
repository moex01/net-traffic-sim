"""Helper utilities for realistic HTTP and content generation."""

from __future__ import annotations

import base64
import json
import os
import random
import uuid
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from email.utils import formatdate

from .config import SHAREPOINT_VULNERABLE_ENDPOINTS, WEB_APP_SCANNER_ENDPOINTS

_CONTEXT_RNG: ContextVar[random.Random | None] = ContextVar("net_traffic_sim_rng", default=None)
_SHAREPOINT_IDS: ContextVar[dict | None] = ContextVar("net_traffic_sim_sharepoint_ids", default=None)


def set_context_rng(rng: random.Random | None) -> None:
    """Set a per-context RNG used for deterministic identifiers."""
    _CONTEXT_RNG.set(rng)


def _get_rng():
    rng = _CONTEXT_RNG.get()
    return rng if rng is not None else random


def _random_bytes(rng, length: int) -> bytes:
    if hasattr(rng, "getrandbits"):
        return int(rng.getrandbits(length * 8)).to_bytes(length, "big")
    return os.urandom(length)


def _uuid_from_rng(rng) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def init_sharepoint_ids() -> None:
    """Initialize SharePoint GUID pools for the active context."""
    rng = _get_rng()
    _SHAREPOINT_IDS.set(
        {
            "library_guids": {name: _uuid_from_rng(rng) for name in _SHAREPOINT_LIBRARY_NAMES},
            "view_guids": [_uuid_from_rng(rng) for _ in range(12)],
        }
    )


def _get_sharepoint_ids() -> dict:
    ids = _SHAREPOINT_IDS.get()
    if ids is None:
        init_sharepoint_ids()
        ids = _SHAREPOINT_IDS.get() or {}
    return ids


def generate_random_guid() -> str:
    """Return a UUID string suitable for IDs in URLs or logs."""
    rng = _get_rng()
    if hasattr(rng, "getrandbits"):
        return _uuid_from_rng(rng)
    return str(uuid.uuid4())


def format_guid_for_url(guid: str) -> str:
    """Normalize GUID formatting for URL parameters."""
    return guid.strip("{}").lower()


def generate_correlation_id() -> str:
    """Return a correlation ID used to tie requests to responses."""
    rng = _get_rng()
    if hasattr(rng, "getrandbits"):
        return _uuid_from_rng(rng)
    return str(uuid.uuid4())


def generate_request_duration() -> int:
    """Return a realistic request duration in milliseconds."""
    rng = _get_rng()
    return int(rng.triangular(5, 1800, 120))


def generate_etag() -> str:
    """Generate a weak ETag value."""
    rng = _get_rng()
    if hasattr(rng, "getrandbits"):
        token = f"{rng.getrandbits(64):016x}"
    else:
        token = uuid.uuid4().hex[:16]
    return f'W/"{token}"'


def generate_session_cookie() -> str:
    """Generate a session cookie value."""
    rng = _get_rng()
    token = base64.urlsafe_b64encode(_random_bytes(rng, 18)).decode("ascii").rstrip("=")
    return token


def generate_request_digest() -> str:
    """Generate a CSRF-like request digest token."""
    rng = _get_rng()
    token = base64.urlsafe_b64encode(_random_bytes(rng, 12)).decode("ascii").rstrip("=")
    return token


def format_http_date(timestamp: float | None = None) -> str:
    """Return RFC 1123 date string for HTTP headers."""
    if timestamp is None:
        timestamp = datetime.now(tz=timezone.utc).timestamp()
    return formatdate(timeval=timestamp, usegmt=True)


def generate_realistic_created_date() -> str:
    """Return a plausible document creation timestamp (ISO 8601)."""
    rng = _get_rng()
    days_ago = rng.randint(1, 730)
    created = datetime.now(tz=timezone.utc) - timedelta(days=days_ago, hours=rng.randint(0, 23))
    return created.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_realistic_document_title() -> str:
    """Generate a realistic document title for portal content."""
    rng = _get_rng()
    subjects = [
        "Quarterly Forecast",
        "Incident Response Plan",
        "Vendor Agreement",
        "Budget Overview",
        "Security Checklist",
        "Project Charter",
        "Operations Runbook",
        "Compliance Update",
        "Risk Assessment",
    ]
    suffixes = ["Draft", "Final", "v2", "v3", "2024", "2025"]
    return f"{rng.choice(subjects)} {rng.choice(suffixes)}"


def generate_realistic_user_agent() -> str:
    """Return a user-agent string typical for enterprise desktops."""
    rng = _get_rng()
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/121.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]
    return rng.choice(user_agents)


def generate_server_versions() -> tuple[str, str | None]:
    """Return server and application runtime version headers."""
    rng = _get_rng()
    server_variants = [
        ("Microsoft-IIS/10.0", "ASP.NET"),
        ("nginx/1.24.0", None),
        ("Apache/2.4.58 (Win64)", None),
    ]
    return rng.choice(server_variants)


_SHAREPOINT_LIBRARY_NAMES = [
    "Documents",
    "Shared Documents",
    "Policies",
    "Templates",
    "Projects",
    "HR",
    "Finance",
    "IT",
    "Operations",
]


def generate_sharepoint_health_score() -> int:
    """Return a plausible SharePoint health score value."""
    rng = _get_rng()
    return rng.choices(
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        weights=[45, 25, 10, 6, 4, 3, 2, 2, 1, 1, 1],
    )[0]


def generate_sharepoint_request_guid() -> str:
    """Return a SharePoint-style request GUID."""
    rng = _get_rng()
    if hasattr(rng, "getrandbits"):
        return _uuid_from_rng(rng)
    return str(uuid.uuid4())


def generate_sharepoint_list_guid() -> str:
    """Return a list GUID from the known library set."""
    ids = _get_sharepoint_ids().get("library_guids", {})
    rng = _get_rng()
    return rng.choice(list(ids.values())) if ids else generate_random_guid()


def generate_view_guid() -> str:
    """Return a view GUID for SharePoint list views."""
    ids = _get_sharepoint_ids().get("view_guids", [])
    rng = _get_rng()
    return rng.choice(ids) if ids else generate_random_guid()


def get_random_library_name() -> str:
    """Return a SharePoint library name."""
    rng = _get_rng()
    return rng.choice(_SHAREPOINT_LIBRARY_NAMES)


def get_library_guid(library_name: str) -> str:
    """Return the GUID associated with a SharePoint library."""
    ids = _get_sharepoint_ids().get("library_guids", {})
    rng = _get_rng()
    return ids.get(library_name, _uuid_from_rng(rng) if hasattr(rng, "getrandbits") else str(uuid.uuid4()))


def generate_sharepoint_json_response(kind: str, item_count: int) -> str:
    """Generate a SharePoint-style JSON response payload."""
    rng = _get_rng()
    items = []
    for _ in range(item_count):
        title = generate_realistic_document_title()
        created = datetime.now(tz=timezone.utc) - timedelta(days=rng.randint(1, 730))
        modified = created + timedelta(days=rng.randint(0, 90), hours=rng.randint(0, 12))
        items.append(
            {
                "Id": rng.randint(1, 5000),
                "Title": title,
                "FileLeafRef": f"{title}.docx",
                "FileRef": f"/Shared Documents/{title}.docx",
                "Created": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "Modified": modified.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "AuthorId": rng.randint(1, 200),
                "EditorId": rng.randint(1, 200),
            }
        )

    payload = {"d": {"results": items}}
    if kind == "list_metadata":
        payload["d"]["Title"] = get_random_library_name()
        payload["d"]["ItemCount"] = item_count

    return json.dumps(payload)


def build_realistic_http_headers(
    *,
    method: str,
    uri: str,
    host: str,
    user_agent: str,
    src_ip: str,
    has_body: bool,
    body_length: int,
    referer: str | None,
    is_api_call: bool,
    request_timestamp: float | None,
    close_connection: bool,
    session_cookie: str | None = None,
    cached_etag: str | None = None,
    cached_last_modified: float | None = None,
) -> str:
    """Build a realistic HTTP/1.1 request header block."""
    if request_timestamp is None:
        request_timestamp = datetime.now(tz=timezone.utc).timestamp()

    headers = [f"{method} {uri} HTTP/1.1"]
    headers.append(f"Host: {host}")
    headers.append(f"User-Agent: {user_agent}")

    if is_api_call:
        headers.append("Accept: application/json")
        headers.append("X-Requested-With: XMLHttpRequest")
    else:
        headers.append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        headers.append("Upgrade-Insecure-Requests: 1")

    headers.append("Accept-Language: en-US,en;q=0.9")
    headers.append("Accept-Encoding: gzip, deflate")

    if referer:
        headers.append(f"Referer: {referer}")

    if session_cookie:
        headers.append(f"Cookie: session_id={session_cookie}")

    if cached_etag and cached_last_modified is not None:
        headers.append(f"If-None-Match: {cached_etag}")
        headers.append(f"If-Modified-Since: {format_http_date(cached_last_modified)}")

    if has_body:
        if is_api_call:
            headers.append("Content-Type: application/json")
        else:
            headers.append("Content-Type: application/x-www-form-urlencoded")
        headers.append(f"Content-Length: {body_length}")

    connection_value = "close" if close_connection else "keep-alive"
    headers.append(f"Connection: {connection_value}")
    headers.append("")
    headers.append("")

    return "\r\n".join(headers)


def should_use_range_request(filesize: int, filename: str) -> tuple[bool, int, int]:
    """Decide whether to use HTTP Range requests for a download."""
    if filesize < 10 * 1024 * 1024:
        return False, 1, filesize

    rng = _get_rng()
    num_ranges = rng.randint(2, 6)
    if filename.lower().endswith(".iso"):
        num_ranges = max(num_ranges, 4)
    range_size = max(1024 * 1024, int(filesize / num_ranges))
    return True, num_ranges, range_size


def get_web_app_endpoints() -> list[tuple[str, str, str | None]]:
    """Return common portal endpoints for normal user activity."""
    return [
        ("GET", "/", None),
        ("GET", "/login", None),
        ("POST", "/login", "username=user&password=***"),
        ("GET", "/dashboard", None),
        ("GET", "/profile", None),
        ("GET", "/docs", None),
        ("GET", "/docs/policies", None),
        ("GET", "/docs/handbook", None),
        ("GET", "/search", None),
        ("POST", "/api/v1/search", '{"query":"project charter"}'),
        ("GET", "/api/v1/notifications", None),
        ("POST", "/api/v1/feedback", '{"rating":4,"comment":"ok"}'),
        ("GET", "/assets/app.css", None),
        ("GET", "/assets/app.js", None),
        ("GET", "/assets/logo.png", None),
        ("GET", "/favicon.ico", None),
    ]


def get_sharepoint_endpoints() -> list[tuple[str, str, str | None]]:
    """Return SharePoint endpoints for normal portal activity."""
    library_name = get_random_library_name()
    list_guid = generate_sharepoint_list_guid()
    view_guid = generate_view_guid()
    doc_guid = generate_random_guid().upper()
    item_id = random.randint(1, 5000)

    process_query_body = (
        '<Request AddExpandoFieldTypeSuffix="true" '
        'SchemaVersion="15.0.0.0" '
        'LibraryVersion="16.0.0.0" '
        'ApplicationName="SharePoint" '
        'xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009">'
        "<Actions>"
        f'<ObjectPath Id="2" ObjectPathId="1" />'
        "</Actions>"
        "<ObjectPaths>"
        f'<Method Id="1" ParentId="0" Name="GetItemById">'
        f'<Parameters><Parameter Type="Number">{item_id}</Parameter></Parameters>'
        "</Method>"
        '<Identity Id="0" Name="{list_guid}" />'
        "</ObjectPaths>"
        "</Request>"
    )

    return [
        ("GET", "/_layouts/15/start.aspx", None),
        ("GET", "/_layouts/15/viewlsts.aspx", None),
        ("GET", "/_layouts/15/Doc.aspx", None),
        ("GET", f"/_layouts/15/Doc.aspx?sourcedoc=%7B{doc_guid}%7D", None),
        ("GET", f"/_api/web/lists(guid'{list_guid}')/items?$top=20", None),
        ("GET", f"/_api/web/lists/getbytitle('{library_name}')/items?$select=Id,Title,Modified", None),
        ("GET", f"/_api/web/lists/getbytitle('{library_name}')/views(guid'{view_guid}')", None),
        ("POST", "/_vti_bin/client.svc/ProcessQuery", process_query_body),
        ("POST", "/_api/web/GetFileByServerRelativeUrl('/Shared Documents')/ListItemAllFields", "{}"),
    ]


def get_scanner_endpoints() -> list[tuple[str, str, int]]:
    """Return scanner endpoints for background internet noise."""
    return list(WEB_APP_SCANNER_ENDPOINTS)


def get_vulnerable_endpoints() -> list[tuple[str, str, int]]:
    """Return SharePoint endpoints targeted by exploit scanners."""
    return list(SHAREPOINT_VULNERABLE_ENDPOINTS)
