| case | rule ids fired (direct mode) |
|---|---|
| nosql $ne login | - |
| nosql $where | sigma:be88336f-ab43-4572-b22f-f67eaae301df |
| nosql query [$regex] | - |
| proto pollution json | - |
| proto pollution query | - |
| constructor.prototype | - |
| mass assignment role | - |
| CRLF in query | - |
| open redirect // | - |
| open redirect https | - |
| ssrf decimal ip | web.ssrf |
| ssrf hex ip | web.ssrf |
| ssrf octal ip | web.ssrf |
| ssrf ipv6-mapped | web.ssrf |
| ssrf aws ipv6 | sigma:d76230ce-dd7a-4d84-a073-d8de5d91b70b, web.ssrf |
| ssrf gcp name | sigma:d76230ce-dd7a-4d84-a073-d8de5d91b70b, web.ssrf |
| ssrf nip.io | sigma:d76230ce-dd7a-4d84-a073-d8de5d91b70b, web.ssrf |
| ssrf localhost | web.ssrf |
| ssrf 0.0.0.0 | web.ssrf |
| ssrf gopher | sigma:d76230ce-dd7a-4d84-a073-d8de5d91b70b, web.ssrf |
| ssrf file:// | sigma:6622a926-1e5b-4905-b8be-919682073137, sigma:e9c1a34a-6610-4569-b5ae-1a23ce7790ad, web.lfi_rfi, web.path_traversal |
| jwt alg none (Authorization) | - |
| jwt kid traversal (Authorization) | - |
| graphql introspection | sigma:3c8aa795-ee7b-495a-9c73-70f15a08c006 |
| graphql batch 50 | - |
| graphql alias brute | - |
| upload .php | web.lfi_rfi |
| upload .phtml/.jpg.php | - |
| host header injection | - |
| IDOR enum /api/orders/1000..1060 all 200 (n=60) | - |
| IDOR enum 403/200 mix (n=60) | - |
| account enum 60 usernames 401 (n=60) | ai.adaptive_mutation, web.credential_stuffing |
| password spray 30 x 401 slow (60s) (n=30) | ai.adaptive_mutation |
| forgot-password enum 60 x 200/404 (n=60) | ai.adaptive_mutation |