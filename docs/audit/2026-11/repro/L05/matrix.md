| technique | sqli | xss | traversal | cmdi | ssti | ssrf | log4shell | deser_php | lfi_wrapper |
|---|---|---|---|---|---|---|---|---|---|
| plain(1x url) | W | W | W | W | W | W | W | W | W |
| url 2x | W | W | W | W | W | W | W | W | W |
| url 3x | W | W | W | W | W | W | W | W | W |
| url 4x | - | - | - | - | W | W | - | - | - |
| %uXXXX | W | W | W | W | W | W | W | W | W |
| overlong utf8 | W | W | W | W | W | W | W | W | W |
| fullwidth | W | W | W | W | W | W | W | - | W |
| html &#dd; | W | W | W | W | W | W | W | W | W |
| html &#xh (no ;) | W | - | W | - | W | - | W | - | - |
| html named | W | W | W | W | W | W | W | W | W |
| random case | W | W | W | W | W | W | W | - | W |
| ws tab | W | W | W | W | W | W | W | W | W |
| ws %0b | W | W | W | W | W | W | W | W | W |
| ws %a0 | - | W | W | w | W | W | W | W | W |
| ws /**/ | W | W | W | w | W | W | W | W | W |
| base64 param | - | - | - | - | - | - | - | - | - |
| json body | W | W | W | W | W | W | W | W | W |
| json \u escapes | W | W | W | W | W | W | W | W | W |
| json nested string | W | W | W | W | W | W | W | - | W |
| json 128 leaves first | S | S | S | S | S | S | W | - | S |
| json key | S | S | S | S | S | S | W | - | S |
| json utf-16 body | - | - | - | - | - | - | - | - | - |
| graphql variables | W | W | W | W | W | W | W | W | W |
| multipart | W | W | W | W | W | W | W | W | W |
| multipart xboundary confusion | S | S | S | S | S | S | W | W | S |
| xml element | W | W | W | W | W | W | W | W | W |
| header Referer | W | W | - | W | W | W | W | W | W |
| header X-Forwarded-Host | W | W | - | W | W | W | W | W | W |
| custom header X-Tenant-Id | - | - | - | - | W | W | W | W | - |
| path segment | W | W | W | W | W | W | W | W | W |
| path ;matrix param | W | W | W | W | W | W | W | W | W |
| HPP split (ASP.NET join) | S | W | W | w | W | W | W | W | W |
| after 8192 chars same param | S | S | S | S | S | S | S | - | S |
Legend: W=expected web.* detector fired, w=other web.* detector only, S=Sigma only, -=nothing. Mode: direct (event as sent; no Gate redaction).
