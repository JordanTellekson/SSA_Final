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

The system maps numeric risk scores (0–100) into classification levels:

- Low (0–24): Minimal suspicious indicators
- Medium (25–49): Some suspicious patterns present
- High (50–74): Strong indicators of phishing behavior
- Critical (75–100): Highly likely or confirmed phishing activity

### Rationale

Lower scores represent domains with few or weak signals.  
Higher scores reflect multiple strong indicators such as typosquatting, suspicious subdomains, or abnormal patterns.

### Validation Examples

- google.com → Low  
- amazon.com → Low  
- paypa1-login-secure.com → High  
- verify-account-paypal-alert.xyz → Critical  
- randomdomain123.biz → Medium  

Safe domains should not reach High or Critical classifications.
