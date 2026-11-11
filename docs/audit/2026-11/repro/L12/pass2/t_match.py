from tokiwa.intel.matcher import match_software, compare_versions
cases = [
 ("apache httpd 2.4.49 exact CPE (CVE-2021-41773) vs Debian pkg", {"vendor":"apache","product":"http_server","version":"2.4.49-1"}, {"cpe":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}),
 ("same, asset plain 2.4.49", {"vendor":"apache","product":"http_server","version":"2.4.49"}, {"cpe":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}),
 ("nginx endIncluding 1.18.0 vs ubuntu 1.18.0-6ubuntu14.4", {"vendor":"f5","product":"nginx","version":"1.18.0-6ubuntu14.4"}, {"cpe":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*","versionEndIncluding":"1.18.0"}),
 ("spring endIncluding 5.3.17 vs 5.3.17.RELEASE", {"vendor":"vmware","product":"spring_framework","version":"5.3.17.RELEASE"}, {"cpe":"cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*","versionEndIncluding":"5.3.17"}),
 ("hibernate exact 5.4.0 vs 5.4.0.Final", {"vendor":"hibernate","product":"hibernate_orm","version":"5.4.0.Final"}, {"cpe":"cpe:2.3:a:hibernate:hibernate_orm:5.4.0:*:*:*:*:*:*:*"}),
 ("openssl RHEL 1.1.1k-9.el8 vs endExcl 1.1.1l", {"vendor":"openssl","product":"openssl","version":"1.1.1k-9.el8_7"}, {"cpe":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","versionEndExcluding":"1.1.1l"}),
 ("log4j endExcl 2.15.0 vs 2.14.1", {"vendor":"apache","product":"log4j","version":"2.14.1"}, {"cpe":"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*","versionStartIncluding":"2.0.1","versionEndExcluding":"2.15.0"}),
 ("asset vendor typed 'Apache Software Foundation'", {"vendor":"Apache Software Foundation","product":"HTTP Server","version":"2.4.49"}, {"cpe":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}),
 ("asset product typed 'httpd'", {"vendor":"apache","product":"httpd","version":"2.4.49"}, {"cpe":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}),
 ("asset product 'Apache HTTP Server' no vendor", {"product":"Apache HTTP Server","version":"2.4.49"}, {"cpe":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}),
 ("openssh 8.9p1 vs endExcl 9.3p2", {"vendor":"openbsd","product":"openssh","version":"8.9p1"}, {"cpe":"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*","versionEndExcluding":"9.3"}),
 ("openssh exact 9.3 p1 update field vs 9.3p1", {"vendor":"openbsd","product":"openssh","version":"9.3p1"}, {"cpe":"cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*"}),
 ("OSV pypi django 4.2.0 vs fixed 4.2.8", {"product":"django","ecosystem":"PyPI","version":"4.2.0"}, {"product":"django","ecosystem":"PyPI","ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"4.2"},{"fixed":"4.2.8"}]}]}),
]
for name,a,v in cases:
    m=match_software(a,v); print(f"{'MATCH' if m else 'miss '} {name} :: {m.confidence if m else ''} {m.reason[:110] if m else ''}")
print(compare_versions("1.18.0-6ubuntu14.4","1.18.0"), compare_versions("5.3.17.RELEASE","5.3.17"), compare_versions("2.4.49-1","2.4.49"))
