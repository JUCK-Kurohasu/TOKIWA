"""web.ssrf - server-side request forgery attempts (internal/loopback/metadata targets, gopher:// dict://).

Matches parameter *values* (query/body/cookie) so a ``Referer: http://localhost:3000/`` from a developer's browser
does not alert. Cloud metadata endpoints are also matched in the path (open-proxy probing) and headers.
Includes the well-known alternate spellings of 127.0.0.1 / 169.254.169.254 (decimal, hex, octal, IPv4-mapped
IPv6). Known limitation: DNS names that *resolve* to internal addresses (rebinding, nip.io style) are not
resolved here - detection is lexical.
"""

from __future__ import annotations

from tokiwa.detect.base import register_detector
from tokiwa.detect.web_common import (
    BODY,
    COOKIE,
    HEADER,
    HEADER_OTHER,
    PATH,
    QUERY,
    WebSignatureDetector,
    sig,
)
from tokiwa.schemas.common import Severity

_H, _M = Severity.HIGH, Severity.MEDIUM

_VALUES = frozenset({QUERY, BODY, COOKIE})
_METADATA_LOCATIONS = frozenset({QUERY, BODY, COOKIE, PATH, HEADER, HEADER_OTHER})

_INTERNAL_HOST = (
    r"(?:localhost|127(?:\.\d{1,3}){1,3}|0\.0\.0\.0|0x7f[0-9a-f]{0,6}|0177(?:\.0{1,4}){0,3}\.0{0,3}1|2130706433"
    r"|0(?=[:/\]?#]|$)|::1?|0:0:0:0:0:0:0:1|::ffff:127\.0\.0\.1|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2}|f[cd][0-9a-f]{2}:[0-9a-f:]{0,40}"
    r"|fe80:[0-9a-f:%]{0,40}|[\w.-]{1,100}\.(?:internal|local|localdomain|localhost|lan|intranet|corp|svc"
    r"|cluster\.local))"
)


@register_detector
class SsrfDetector(WebSignatureDetector):
    id = "web.ssrf"
    name = "SSRF attempt"
    description = (
        "A URL or host parameter points at loopback/private/link-local addresses, cloud instance metadata "
        "(169.254.169.254, metadata.google.internal) or uses gopher://, dict:// and similar SSRF-friendly schemes."
    )
    family = "ssrf"
    mitre = ("T1190",)
    default_severity = _H
    locations = _VALUES
    signatures = (
        sig(
            "ssrf.cloud_metadata",
            r"169\.254\.169\.254|\bmetadata\.google\.internal\b|\bmetadata\.azure\.com\b|\b100\.100\.100\.200\b"
            r"|\bfd00:ec2::254\b|\b169\.254\.170\.2\b|\binstance-data(?:\.ec2\.internal)?\b"
            r"|/latest/(?:meta-data|user-data|dynamic|api/token)\b|/computemetadata/v1\b|/metadata/identity/oauth2\b"
            r"|/opc/v[12]/instance\b|\b2852039166\b|\b0xa9fea9fe\b|\b0251\.0376\.0251\.0376\b|::ffff:a9fe:a9fe",
            _H,
            confidence=0.85,
            view="lower",
            locations=_METADATA_LOCATIONS,
            description="cloud instance metadata endpoint",
            mitre=("T1552.005",),
        ),
        sig(
            "ssrf.internal_url",
            r"\b(?:https?|ftps?|gopher|dict|ldaps?|tftp|jar|netdoc|wss?|sftp|smb)://(?:[^/@?#\s]{0,64}@)?\[?"
            + _INTERNAL_HOST
            + r"\]?(?:[:/?#\]]|$)",
            _H,
            confidence=0.7,
            view="value",
            description="URL pointing at a loopback/private/internal host",
        ),
        sig(
            "ssrf.dangerous_scheme",
            r"(?<!jndi:)\b(?:gopher|dict|ldaps?|tftp|jar|netdoc|rmi)://",
            _H,
            confidence=0.8,
            view="value",
            description="SSRF-friendly URL scheme (gopher://, dict://)",
        ),
        sig(
            "ssrf.bare_internal_host",
            r"^\[?(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|::1|169\.254(?:\.\d{1,3}){2}|0x7f[0-9a-f]{6}|2130706433)"
            r"\]?(?::\d{1,5})?(?:/\S{0,200})?$",
            _M,
            confidence=0.5,
            view="value",
            description="parameter value is a loopback/link-local host",
        ),
    )
