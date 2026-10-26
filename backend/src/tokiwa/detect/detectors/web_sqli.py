"""web.sqli - SQL injection attempts (UNION, boolean/time-based blind, stacked queries, catalog probing).

Patterns run on the ``norm`` view (decoded, lower-cased, ``/**/`` comments removed, whitespace collapsed), so
``UnIoN/**/SeLeCt``, ``union%0aselect`` and ``/*!50000union*/`` all read ``union select``. Plain English such as
a search for "select a dress" or "SELECT * FROM wishlist" does not match: every pattern needs SQL structure
(quote breakout + operator, a UNION column list, a stacked statement after ``;``, a DB catalog name ...).
"""

from __future__ import annotations

from tokiwa.detect.base import register_detector
from tokiwa.detect.web_common import WebSignatureDetector, sig
from tokiwa.schemas.common import Severity

_H, _M = Severity.HIGH, Severity.MEDIUM


@register_detector
class SqliDetector(WebSignatureDetector):
    id = "web.sqli"
    name = "SQL injection attempt"
    description = (
        "SQL injection payload in a request parameter, path, cookie or reflected header "
        "(UNION-based, boolean/time-based blind, stacked queries, catalog enumeration)."
    )
    family = "sqli"
    mitre = ("T1190",)
    default_severity = _H
    signatures = (
        sig(
            "sqli.union_select",
            r"\bunion(?: (?:all|distinct))? ?\(? ?select\b ?(?:\(|null\b|\d|@@|'|\"|\*|[a-z_][\w.]{0,40} ?(?:,|\(|\bfrom\b))",
            _H,
            confidence=0.85,
            description="UNION SELECT",
        ),
        sig(
            "sqli.time_based",
            r"\b(?:sleep ?\( ?\d{1,3}(?:\.\d{1,3})? ?\)|pg_sleep ?\(|benchmark ?\( ?\d{3,}|waitfor (?:delay|time) ?'"
            r"|dbms_pipe\.receive_message ?\(|dbms_lock\.sleep ?\(|randomblob ?\( ?\d{6,})",
            _H,
            confidence=0.85,
            description="time-based blind (SLEEP/BENCHMARK/pg_sleep/WAITFOR DELAY)",
        ),
        sig(
            "sqli.tautology_quoted",
            r"['\"`)] ?(?:or|and|xor|\|\||&&) ?\(? ?(?:\d{1,10} ?(?:=|<>|!=|<=>) ?\d{1,10}\b"
            r"|['\"][^'\"]{0,20}['\"] ?(?:=|<>|!=|like) ?['\"]|true\b|false\b|not\b|\d{1,10} ?(?:--|#|$)"
            r"|[a-z_]{1,20} ?\(|exists ?\()",
            _H,
            confidence=0.8,
            description="quote breakout + boolean condition (' OR 1=1)",
        ),
        sig(
            "sqli.tautology_numeric",
            r"(?:\b(?:or|and|xor)|\|\||&&) \(? ?\d{1,10} ?(?:=|<>|!=|<=>) ?\d{1,10}\b ?(?:--|#|\)|;|$)",
            _M,
            confidence=0.6,
            description="numeric boolean condition (OR 1=1)",
        ),
        sig(
            "sqli.comment_terminated",
            r"[\w)]['\"`] ?\)? ?(?:--(?: |$|-|\+)|#(?: |$))",
            _M,
            confidence=0.55,
            description="quote breakout terminated by SQL comment (admin'--)",
        ),
        sig(
            "sqli.stacked_query",
            r"; ?(?:drop (?:table|database|schema)\b|delete from\b|insert into\b|update [\w.`\"\[\]]{1,64} set\b"
            r"|truncate table\b|alter (?:table|user|database)\b|create (?:table|user|database|function|procedure|trigger)\b"
            r"|exec(?:ute)? ?(?:\(|xp_|sp_|master\.|@)|declare @|shutdown\b|grant \w"
            r"|select (?:\*|@@|\d|null\b|[\w.]{1,40} ?(?:,|\bfrom\b|\()))",
            _H,
            confidence=0.8,
            description="stacked query after ';'",
        ),
        sig(
            "sqli.catalog_probe",
            r"\binformation_schema\b|\bsqlite_master\b|\bpg_catalog\b|\bpg_shadow\b|\bsysobjects\b|\bsyscolumns\b"
            r"|\bmysql\.user\b|\bsys\.(?:tables|objects|columns|databases)\b|\ball_tab_columns\b",
            _H,
            confidence=0.8,
            description="database catalog enumeration (information_schema)",
        ),
        sig(
            "sqli.dangerous_function",
            r"\bxp_cmdshell\b|\bload_file ?\(|\binto (?:out|dump)file\b|\bextractvalue ?\(|\bupdatexml ?\("
            r"|\butl_(?:inaddr|http)\.|\bgroup_concat ?\(|@@(?:version|datadir|hostname|basedir)\b|\bsys_eval ?\("
            r"|\bdbms_xmlgen\.|\bconcat(?:_ws)? ?\( ?0x[0-9a-f]{2}|\bchar ?\( ?\d{2,3} ?(?:, ?\d{2,3} ?){3,20}\)",
            _H,
            confidence=0.8,
            description="SQL function used for extraction/RCE (xp_cmdshell, LOAD_FILE, @@version ...)",
        ),
        sig(
            "sqli.order_by_probe",
            r"['\")] ?order by \d{1,3} ?(?:--|#)|\border by \d{1,3} ?(?:--|#)",
            _M,
            confidence=0.55,
            description="ORDER BY column-count probe",
        ),
    )
