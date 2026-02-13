# Cloudflare Example Security Rules
A set of security rules for protecting a public webapp. All the riles are below, you should split them into 3 separate sets: SKIP, BLOCK, CHALLENGE.

- I am explicitly allowing googlebot to discover my sitemap and blocking everything else. You should remove the first line in the block rules and 2nd line in the allow rules if you don't like this approach.
- I am using a blacklist at the end of the challenge rules to address worst offenders via an IP address. You can create a blacklist like this in cloudflare --> Manage Account --> Configurations --> Lists. 

# ALLOW

```
(http.request.uri.path eq "/robots.txt") or
((http.request.uri.path eq "/sitemap.xml") and (lower(http.user_agent) contains "googlebot"))
```

# BLOCK

```
(http.request.uri eq "/sitemap.xml") 
or (http.request.method in {"PUT" "DELETE" "PATCH"}) 
or (http.request.method eq "POST" and http.request.uri ne "/md-to-html") 
or (ip.src.country in {"SG" "CN"}) 
or (ip.src.asnum in {132203 4134 4837 133982 45090 9009 136907}) 
or (any(http.request.headers["accept-language"][*] contains "zh-CN"))
or (
    http.user_agent contains "Applebot" or 
    http.user_agent contains "Bytespider" or 
    http.user_agent contains "facebookexternalhit" or 
    http.user_agent contains "ChatGPT-User" or 
    http.user_agent contains "DuckAssistBot" or 
    http.user_agent contains "GPTBot" or 
    http.user_agent contains "MistralAI-User" or 
    http.user_agent contains "OAI-SearchBot" or 
    http.user_agent contains "Perplexity" or 
    http.user_agent contains "SemrushBot" or 
    http.user_agent contains "Twitterbot" or 
    http.user_agent contains "PetalBot" or 
    http.user_agent contains "Amazonbot" or 
    http.user_agent contains "Claude-SearchBot" or 
    http.user_agent contains "YandexBot" or 
    http.user_agent contains "CCBot" or
    http.user_agent contains "censys.io" or
    http.user_agent contains "2ip"
)
```

# CHALLENGE

```
(ip.src.asnum in {60068 5713 28885 59668 51375 269679 265477 7418 28210 137526 56264 264205 9009 16247 51332 212238 131199 22298 29761 62639 206150 210277 46562 8100 3214 206092 206074 206164 213074 4134 4837 9808 37963 9506 4657 4773 45143 45090 132203 39232 37105 55836 268044 133982 6057 8697 9299 49273 136907 8452 8151 44244 7713 14593 328539 36925 202441 7303 30689 45102 22773 210906 7922 174 214483 5089 215595})

or (ip.src.country in {"AF" "DZ" "AD" "AW" "BD" "BR" "BI" "BO" "CF" "CL" "CN" "CC" "CO" "CG" "DO" "EG" "GF" "GT" "HN" "HK" "IN" "ID" "IR" "IQ" "JO" "KZ" "KE" "KR" "MG" "MY" "MV" "MX" "MD" "MZ" "NI" "PH" "RU" "SA" "SG" "ZA" "SY" "TZ" "TH" "TN" "TR" "TM" "UA" "AE" "UZ" "VE" "VN" "ZM" "TK"})

or (ip.src in $malware)
or (http.user_agent contains "python") 
or (http.user_agent contains "Go-http-client") 
or (http.user_agent contains "brightbot")
or (
  ends_with(http.request.uri.path, ".php") or ends_with(http.request.uri.path, ".jsp") or 
  ends_with(http.request.uri.path, ".sql") or ends_with(http.request.uri.path, ".yml") or 
  ends_with(http.request.uri.path, ".yaml") or ends_with(http.request.uri.path, ".log") or 
  ends_with(http.request.uri.path, ".gz") or ends_with(http.request.uri.path, ".py") or 
  ends_with(http.request.uri.path, ".pyc") or ends_with(http.request.uri.path, ".tfvars") or 
  ends_with(http.request.uri.path, ".tfstate") or ends_with(http.request.uri.path, ".sh")
)
or (
  lower(http.request.uri.path) contains ".git" or lower(http.request.uri.path) contains ".tmp" or 
  lower(http.request.uri.path) contains ".vscode" or lower(http.request.uri.path) contains ".remote" or 
  lower(http.request.uri.path) contains ".production" or lower(http.request.uri.path) contains ".local" or 
  lower(http.request.uri.path) contains ".env" or lower(http.request.uri.path) contains "=env" or 
  lower(http.request.uri.path) contains "live_env" or lower(http.request.uri.path) contains "/wp" or 
  lower(http.request.uri.path) contains "wordpress" or lower(http.request.uri.path) contains ".json" or 
  lower(http.request.uri.path) contains "/laravel" or lower(http.request.uri.path) contains "/php" or 
  lower(http.request.uri.path) contains "/backup" or lower(http.request.uri.path) contains "/github" or 
  lower(http.request.uri.path) contains "/back" or lower(http.request.uri.path) contains "/priv" or 
  lower(http.request.uri.path) contains "/inst" or lower(http.request.uri.path) contains "/admin" or 
  lower(http.request.uri.path) contains "/debug" or lower(http.request.uri.path) contains "/packa" or 
  lower(http.request.uri.path) contains "/.well-known/" or lower(http.request.uri.path) contains "/aws" or 
  lower(http.request.uri.path) contains "/lab" or lower(http.request.uri.path) contains "/test" or 
  lower(http.request.uri.path) contains "/info" or lower(http.request.uri.path) contains "redacted" or 
  lower(http.request.uri.path) contains "config" or lower(http.request.uri.path) contains "credentials" or 
  lower(http.request.uri.path) contains "meteor."
) or

(ip.src in $YOUR_CLOUDFLARE_BLACKLIST_NAME)
