### Phishing Indicators
-   **Excessive subdomains**
    -   Example: `login.paypal.secure.verify.account.com`        
-   **Typosquatting**
    -   Misspelled brands: `paypa1.com`, `g00gle.com`
-   **Homoglyph attacks**
    -   Using lookalike characters (e.g., Cyrillic “а” instead of “a”)
-   **Long or obfuscated URLs**
    -   Very long strings with random characters
-   **Use of URL shorteners**
    -   Bit.ly, TinyURL masking the real domain
-   **Hyphen abuse**
    -   `secure-login-account-update.com`
-   **IP address instead of domain**
    -   `http://192.168.1.1/login`
-   **External phishing blocklist match (high-confidence indicator)**
    -   Domains are cross-referenced against known phishing intelligence feeds during analysis
    -   Primary feed: OpenPhish (https://openphish.com/feed.txt)
    -   If a domain is found in the blocklist, it is immediately flagged as malicious
    -   This overrides all structural risk signals (typosquatting, entropy, etc.)
    -   Risk score is set to maximum (100)
    -   Example behavior: `malicious-login-paypal.com` → instant high-confidence detection
### Advanced Patterns Beyond the Basics
-   **Character distribution anomalies**
    -   High ratio of digits/symbols vs letters
    -   Example: `a9x2k-login-secure123.biz`
-   **Shannon entropy (randomness)**
    -   Phishing domains often look algorithmically generated 
-   **Repeated characters**
    -   `loooogin-paypal.com`
-   **Consonant-heavy or unreadable strings**
    -   `xjkdqwe-login-alert.net`
-   **Brand keyword stuffing**
    -   Multiple brands in one domain:
        -   `paypal-amazon-security-alert.com`
-   **Prefix/suffix abuse**
    -   `secure-`, `verify-`, `update-`, `account-`
-   **Suspicious TLD usage**
    -   `.xyz`, `.top`, `.tk`, `.ru` (not bad alone, but higher risk statistically)
 - -   **Edit distance (Levenshtein distance)**
    -   `paypol.com` vs `paypal.com`    
-   **Keyboard proximity errors**
    -   `gppgle.com` (o → p)

These are **high-signal** for phishing detection.
### WHOIS / Registration Features
We can use pylookup in 
-   **Recently registered domain**
    -   Many phishing domains are < 30 days old
-   **Short domain lifespan**
    -   Registered for only 1 year
-   **Privacy-protected WHOIS info**
-   **Registrar reputation**
-   **Registrar Name**
    -   Some registrars are abused more often
-   **URL encoding tricks**
    -   `%20`, `%2F`, `%3A`
-   **Double encoding**
-   **@ symbol abuse**
    -   `paypal.com@malicious-site.com`
-   **Fragment confusion**
    -   `#login-secure`

### DNS Characteristics

-   **Fast-flux hosting**    
    -   Frequent IP changes    
-   **Low TTL (Time-To-Live) values**
-   **Mismatch between domain and hosting location**
Not all HTTPS is safe—phishing sites use it too.
-   **Free certificates (e.g., Let's Encrypt)**
    -   Not bad alone, but common in phishing
-   **Recently issued certificate**
-   **Domain mismatch in certificate**
-   **No HTTPS at all**
-   **Suspicious issuer patterns**
These require crawling or sandboxing the page.
-   **Login forms on non-legitimate domains**    
-   **Requests for sensitive info**
    -   Passwords, SSN, credit cards   
-   **Copied branding**
    -   Logos from real companies
-   **Minimal or broken functionality**
-   **Heavy use of JavaScript obfuscation**
-   **Auto-redirects**
    -   Especially multiple chained redirects
 ### Structural URL Features
 -   **Deep path nesting**
     -   `/secure/login/account/update/verify/index.php`    
-   **Suspicious file names**
    -   `login.php`, `verify.html`, `update.cgi`
-   **Query parameter abuse**
    -   `?session=...&auth=...&token=...` 
-   **Mixed language patterns**
    -   English + random strings

### External Blocklist Source (OpenPhish)

-   **Provider**
    -   OpenPhish
    -   https://openphish.com/feed.txt
-   **Data Type**
    -   Verified phishing URLs
    -   Normalized to domain-level indicators during analysis
-   **Update Frequency**
    -   The feed is refreshed every 60 minutes
    -   Updates are retrieved via automated background fetch
    -   A locally cached version is used for all analysis requests within the TTL window
    -   Cache expiration triggers a refresh to ensure updated threat intelligence while avoiding rate-limiting
-   **False Positive Rate**
    -   OpenPhish is a curated and actively maintained intelligence feed with a low false-positive rate
    -   False positives may occur in rare cases such as:
        -   Temporarily compromised legitimate domains
        -   Recently cleaned domains still present in cached or historical feed data
    -   Blocklist matches are treated as high-confidence indicators and override all heuristic-based risk scoring
> Written with [StackEdit](https://stackedit.io/).

## Risk Score Classification

The analyzer maps the 0-100 numeric risk score into a named label so analysts and UI views can communicate severity without requiring users to interpret the raw score.

| Score range | Label | Intended meaning |
| --- | --- | --- |
| 0-24 | Low | No signal or only weak isolated signals. |
| 25-49 | Medium | Multiple weak signals or one moderately strong structural pattern. |
| 50-74 | High | Several structural phishing indicators are present together. |
| 75-100 | Critical | High-confidence or heavily reinforced phishing evidence. |

### Classification Rationale

The initial bands are calibrated around the four structural signals that the analyzer already explains in detail:

- Typosquatting/edit distance: close matches to trusted brand roots are strong because small spelling changes are common in credential-harvesting domains.
- Excessive subdomains: long chains such as `login.secure.verify.example.com` often hide the real registrable domain from hurried users.
- Hyphen abuse: repeated hyphen-delimited security words are a common phishing pattern and are more meaningful when combined with other signals.
- Shannon entropy: unusually random registrable labels can indicate automated generation or deliberately obfuscated domains.

Low allows a single weak signal without overstating the threat. Medium captures domains where one or two structural signals deserve analyst attention. High requires enough combined evidence to suggest phishing behavior rather than coincidence. Critical is reserved for high-confidence evidence such as a blocklist match or structural risk reinforced by registration metadata.

### Reference Validation Set

These reference cases are covered by unit tests in `DomainAnalyzerServiceTests` so score changes are reviewed intentionally.

| Domain | Expected band | Validation note |
| --- | --- | --- |
| `google.com` | Low | Known real-world domain with no structural risk signals. |
| `secure-paypal.com` | Low | One weak keyword/hyphen pattern remains below the Medium boundary. |
| `secure-login-account-update.com` | Medium | Keyword, hyphen, and entropy signals combine into the middle band. |
| `account.verify.paypa1-login-secure-update.com` | High | Subdomain, keyword, hyphen, entropy, and composition signals combine. |
| `account.verify.paypa1-login-secure-update.com` with recent/private short registration metadata | Critical | Structural evidence reinforced by registration age, lifespan, and privacy signals. |

False-positive validation is performed against `Legitimate_Domains.txt`, the repository allow-list used by `DomainAnalyzerService`; none of those known-safe domains should classify as High or Critical.
