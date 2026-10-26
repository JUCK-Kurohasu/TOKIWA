"""web.deserialization - serialized-object payloads (Java, PHP, .NET, Python pickle, YAML, node-serialize).

Markers (verified against the serializers' own output):

* Java ``ObjectOutputStream``: magic ``AC ED 00 05`` -> base64 ``rO0AB``; well-known gadget class names
  (commons-collections functors, TemplatesImpl, JdbcRowSetImpl ...); fastjson ``"@type":"com.sun..."``.
* PHP ``serialize()``: ``O:8:"stdClass":1:{`` (object) / ``C:`` (custom).
* .NET BinaryFormatter: header ``00 01 00 00 00 FF FF FF FF`` -> base64 ``AAEAAAD/////``; Json.NET
  ``$type`` gadgets (ObjectDataProvider ...).
* Python pickle: protocol 2/3 ``\\x80\\x02``/``\\x80\\x03`` -> ``gAJ``/``gAN``; protocol 4/5 framed -> ``gASV``/
  ``gAWV``; protocol 0 text ``cposix\\nsystem``.
* YAML tags (``!!python/object/apply:``), node-serialize ``_$$ND_FUNC$$_``.

Known limitation: cookies are usually redacted by the sensor (``[REDACTED:cookie]``) before they reach TOKIWA,
so serialized session cookies are only visible when the redaction policy allows it.
"""

from __future__ import annotations

from tokiwa.detect.base import register_detector
from tokiwa.detect.web_common import (
    BODY,
    BODY_RAW,
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

_B64_EDGE = r"(?:^|[^A-Za-z0-9+/])"


@register_detector
class DeserializationDetector(WebSignatureDetector):
    id = "web.deserialization"
    name = "Insecure deserialization payload"
    description = (
        'Serialized object or gadget-chain marker (Java rO0AB/aced0005, PHP O:n:"Class", .NET AAEAAAD/////, '
        "Python pickle, YAML !!python tags, node-serialize) in a body, parameter, cookie or header."
    )
    family = "deserialization"
    mitre = ("T1190", "T1059")
    default_severity = _H
    locations = frozenset({PATH, QUERY, BODY, BODY_RAW, COOKIE, HEADER, HEADER_OTHER})
    signatures = (
        sig(
            "deser.java_b64",
            _B64_EDGE + r"rO0AB[A-Za-z0-9+/=_-]{4}",
            _H,
            confidence=0.85,
            view="decoded",
            description="Java serialized object (base64 rO0AB)",
        ),
        sig(
            "deser.java_hex",
            r"(?:^|[^0-9a-f])aced0005[0-9a-f]{4}",
            _H,
            confidence=0.85,
            view="lower",
            description="Java serialized object (hex aced0005)",
        ),
        sig(
            "deser.java_gadget",
            r"\b(?:org\.apache\.commons\.collections4?\.(?:functors|keyvalue)|org\.apache\.commons\.beanutils\.beancomparator"
            r"|com\.sun\.org\.apache\.xalan\.internal\.xsltc\.trax\.templatesimpl|com\.sun\.rowset\.jdbcrowsetimpl"
            r"|org\.springframework\.context\.support\.classpathxmlapplicationcontext|java\.rmi\.server\.unicastref"
            r"|sun\.rmi\.server\.unicastref|javax\.management\.badattributevalueexpexception"
            r"|org\.codehaus\.groovy\.runtime\.convertedclosure|ysoserial"
            r"|com\.mchange\.v2\.c3p0\.(?:jndirefforwardingdatasource|wrapperconnectionpooldatasource)"
            r"|org\.apache\.xbean\.propertyeditor\.jndiconverter|bsh\.xthis)\b",
            _H,
            confidence=0.85,
            view="lower",
            description="Java deserialization gadget class",
        ),
        sig(
            "deser.json_polymorphic",
            r"[\"']@type[\"']\s{0,5}:\s{0,5}[\"'](?:com\.sun\.|org\.apache\.|java\.(?:net|lang|rmi)\.|javax\.|com\.alibaba\."
            r"|ch\.qos\.|org\.springframework\.|com\.mchange\.|oracle\.jdbc\.|org\.hibernate\.|com\.zaxxer\.hikari\."
            r"|l(?:com|org|java)\.[\w.]{1,80};|\[(?:com|org|java)\.)",
            _H,
            confidence=0.85,
            view="lower",
            description="fastjson/Jackson polymorphic type gadget (@type)",
        ),
        sig(
            "deser.php_object",
            r"(?:^|[^A-Za-z0-9_])[OC]:\d{1,4}:\"[A-Za-z_\\][\w\\]{0,120}\":\d{1,4}:\{",
            _H,
            confidence=0.85,
            view="decoded",
            description='PHP serialized object (O:n:"Class":n:{)',
        ),
        sig(
            "deser.dotnet_binaryformatter",
            r"AAEAAAD/////",
            _H,
            confidence=0.9,
            view="decoded",
            description=".NET BinaryFormatter payload (AAEAAAD/////)",
        ),
        sig(
            "deser.dotnet_type_gadget",
            r"\$type[\"']?\s{0,5}:\s{0,5}[\"']?system\.(?:windows\.data\.objectdataprovider"
            r"|configuration\.install\.assemblyinstaller|activities\.presentation\.workflowdesigner"
            r"|management\.automation|security\.principal\.windowsidentity|identitymodel\.tokens\.sessionsecuritytoken"
            r"|web\.security\.roleprincipal|data\.services\.internal\.expandedwrapper|diagnostics\.process)"
            r"|\bobjectdataprovider\b[^>]{0,200}\bmethodname\s{0,3}=\s{0,3}[\"']?start\b",
            _H,
            confidence=0.85,
            view="lower",
            description="Json.NET/XAML $type gadget (ObjectDataProvider)",
        ),
        sig(
            "deser.python_pickle_b64",
            _B64_EDGE + r"(?:gASV|gAWV|gAJj|gANj|gAJ9|gAN9|Y29zCnN5c3Rlb|Y3Bvc2l4CnN5c3Rlb|Y19fYnVpbHRpbl9fC)"
            r"[A-Za-z0-9+/=]{4}",
            _M,
            confidence=0.65,
            view="decoded",
            description="Python pickle (base64)",
        ),
        sig(
            "deser.python_pickle_text",
            r"\bc(?:os|posix|nt|subprocess|builtins|__builtin__|commands|pty)\n(?:system|popen|eval|exec|check_output"
            r"|getoutput|call|spawn|run)\b|\b__reduce(?:_ex)?__\b",
            _H,
            confidence=0.8,
            view="lower",
            description="Python pickle opcodes (cposix\\nsystem / __reduce__)",
        ),
        sig(
            "deser.yaml_tag",
            r"!!python/(?:object(?:/apply|/new)?|name|module):|!!javax\.script\.scriptenginemanager"
            r"|!!java\.net\.urlclassloader|!!com\.sun\.rowset|!ruby/(?:object|hash|struct):|!!ruby/object:",
            _H,
            confidence=0.85,
            view="lower",
            description="unsafe YAML tag (!!python/object/apply)",
        ),
        sig(
            "deser.node_serialize",
            r"_\$\$nd_func\$\$_",
            _H,
            confidence=0.9,
            view="lower",
            description="node-serialize function marker (_$$ND_FUNC$$_)",
        ),
    )
