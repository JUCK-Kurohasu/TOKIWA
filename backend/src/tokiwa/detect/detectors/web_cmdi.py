"""web.cmd_injection - OS command injection (;id, |whoami, $(...), backticks, && curl, nc -e, Shellshock).

Runs on the ``lower`` view (decoded, whitespace preserved) because ``%0a`` newline separators matter. Short,
ambiguous commands (``id``, ``ls``, ``pwd``) only count after a strong separator (``;`` newline backtick
``$(`` ``&&`` ``||``) - a single ``|`` is common in filter syntax (``fields=name|id``).
"""

from __future__ import annotations

from tokiwa.detect.base import register_detector
from tokiwa.detect.web_common import ALL_LOCATIONS, WebSignatureDetector, sig
from tokiwa.schemas.common import Severity

_C, _H, _M = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM

_LONG_CMDS = (
    r"(?:/(?:usr/)?s?bin/)?(?:whoami|uname\s{1,3}-[a-z]{1,4}|ifconfig|ipconfig(?:\s{1,3}/all)?|cat\s{1,3}/etc/"
    r"|net\s{1,3}(?:user|localgroup)|systeminfo|nslookup\s|ping\s{1,3}-[cn]\s{0,3}\d|curl\s|wget\s|nc\s{1,3}-"
    r"|ncat\s|bash\s{1,3}-|sh\s{1,3}-[ci]|powershell|cmd(?:\.exe)?\s{1,3}/c|python[23]?\s{1,3}-c|perl\s{1,3}-e"
    r"|ruby\s{1,3}-e|php\s{1,3}-r|sleep\s{1,3}\d{1,3}\b|echo\s{1,3}[\w$'\"]{1,40}\s{0,3}(?:[;|&`>]|$))"
)


@register_detector
class CommandInjectionDetector(WebSignatureDetector):
    id = "web.cmd_injection"
    name = "OS command injection attempt"
    description = (
        "Shell metacharacters followed by system commands, command substitution, download-and-execute chains, "
        "reverse shells or Shellshock function definitions."
    )
    family = "cmd_injection"
    mitre = ("T1190", "T1059", "T1059.004")
    default_severity = _H
    signatures = (
        sig(
            "cmdi.reverse_shell",
            r"/dev/(?:tcp|udp)/[\w.-]{1,64}/\d{1,5}"
            r"|\bnc(?:at)?(?:\.exe)?(?:\s[^\n|;&]{0,80})?\s-[a-z]{0,3}e\s{1,3}(?:/bin/|cmd|powershell|sh\b|bash\b)"
            r"|\bbash\s{1,3}-i\s{0,3}[>&]|\bsh\s{1,3}-i\b|\bmkfifo\s{1,3}/tmp/|\bsocat\s[^\n]{0,80}exec:"
            r"|\bpython[23]?\s{1,3}-c\s{0,3}['\"]?\s{0,3}import\s{1,3}(?:socket|pty|os|subprocess)"
            r"|\bperl\s{1,3}-e\s{0,3}['\"]?\s{0,3}use\s{1,3}socket",
            _C,
            confidence=0.9,
            view="lower",
            description="reverse shell (/dev/tcp, nc -e, bash -i)",
        ),
        sig(
            "cmdi.shellshock",
            r"\(\)\s{0,3}\{\s{0,3}[^}]{0,20};\s{0,3}\}\s{0,3};",
            _C,
            confidence=0.95,
            view="lower",
            locations=ALL_LOCATIONS,
            description="Shellshock function definition (CVE-2014-6271)",
        ),
        sig(
            "cmdi.download_exec",
            r"\b(?:curl|wget)\s[^\n|;&]{0,200}\|\s{0,3}(?:ba|z|da|k)?sh\b"
            r"|\b(?:curl|wget)\s[^\n;&|]{0,200}(?:-o|-O|--output)\s{0,3}/tmp/|\bchmod\s{1,3}\+?[0-7x]{1,4}\s{1,3}/tmp/",
            _H,
            confidence=0.85,
            view="lower",
            description="download-and-execute chain (curl ... | sh)",
        ),
        sig(
            "cmdi.separator_command",
            rf"(?:[;\n\r`]|\$\(|&&|\|\|?)\s{{0,3}}{_LONG_CMDS}",
            _H,
            confidence=0.8,
            view="lower",
            description="shell separator followed by a command (;cat /etc/passwd, |whoami)",
        ),
        sig(
            "cmdi.separator_short",
            r"(?:[;\n\r`]|\$\(|&&|\|\|)\s{0,3}(?:id|pwd|ls(?:\s{1,3}-[a-z]{1,4})?|ps\s{1,3}(?:aux|-ef))\s{0,3}(?:[;|&`#)]|$)",
            _H,
            confidence=0.75,
            view="lower",
            description="strong separator followed by a short command (;id)",
        ),
        sig(
            "cmdi.subshell",
            r"\$\(\s{0,3}(?:id|whoami|uname|cat|curl|wget|sleep|ls|echo|nslookup|dig|ping|bash|sh|python[23]?|perl"
            r"|nc|hostname|base64|printf|env)\b|\$\{ifs\}|\$ifs\b",
            _H,
            confidence=0.85,
            view="lower",
            description="command substitution $(...) / ${IFS}",
        ),
        sig(
            "cmdi.backtick",
            r"`\s{0,3}(?:id|whoami|uname(?:\s{1,3}-[a-z]{1,4})?|hostname|pwd|cat\s{1,3}/[\w./-]{1,60}"
            r"|(?:curl|wget|nslookup|ping)\s{1,3}[^`\n]{1,100}|sleep\s{1,3}\d{1,3}|ls(?:\s{1,3}-[a-z]{1,4})?)\s{0,3}`",
            _M,
            confidence=0.6,
            view="lower",
            description="backtick command substitution",
        ),
        sig(
            "cmdi.shell_path",
            r"(?:^|[\s;|&`'\"(=])/bin/(?:ba|z|da|k|c|tc)?sh\b|\bcmd(?:\.exe)?\s{1,3}/[ck]\s"
            r"|\bpowershell(?:\.exe)?\s[^\n]{0,40}-(?:e|ec|enc|encodedcommand|nop|noprofile|w\s{1,3}hidden"
            r"|windowstyle|c|command|executionpolicy)\b|\biex\s{0,3}\(|\binvoke-expression\b|\bdownloadstring\s{0,3}\(",
            _H,
            confidence=0.75,
            view="lower",
            description="shell interpreter invocation (/bin/sh, cmd /c, powershell -enc)",
        ),
    )
