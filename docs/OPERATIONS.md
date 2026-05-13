# SSA Final Operations Handoff

## Local Runbook

1. Install the .NET SDK that supports `net10.0`.
2. Restore and build from the repository root:

```powershell
dotnet restore .\SSA_Final.Tests\SSA_Final.Tests.csproj
dotnet build .\SSA-Final\SSA-Final.csproj
```

3. Apply Entity Framework migrations to the configured SQL Server database:

```powershell
dotnet ef database update --project .\SSA-Final\SSA-Final.csproj
```

If `dotnet ef` is not installed, install the EF tool first:

```powershell
dotnet tool install --global dotnet-ef
```

4. Run the web app:

```powershell
dotnet run --project .\SSA-Final\SSA-Final.csproj
```

5. Open the local URL shown by `dotnet run`, sign in, and use the dashboard to submit a base domain scan.

## Architecture

The architecture diagram lives in `docs/architecture.mmd`. It shows the primary scan flow:

`User -> DashboardController -> Channel<Guid> -> ScanBackgroundService -> DomainGeneratorService -> DomainAnalyzerService -> PhishingBlocklistService / SslCertificateChecker / RdapDomainRegistrationLookupService -> SqlScanStoreService -> SQL Server`.

It also includes the OpenPhish feed ingestion path and the high-risk report path added for stakeholder briefings.

## Configuration Keys

Configuration is stored in `SSA-Final/appsettings.json` and environment-specific overrides such as `appsettings.Development.json`.

| Key | Purpose |
| --- | --- |
| `ConnectionStrings:SSA_FinalContextConnection` | SQL Server connection string for Identity, scans, and variant results. |
| `DomainAnalyzer:TimeoutSeconds` | Timeout for HTTP/HTML analysis requests. |
| `DomainAnalyzer:RdapTimeoutSeconds` | Timeout for RDAP registration lookup requests. |
| `DomainAnalyzer:RegistrationLookupCacheMinutes` | How long registration lookup responses are cached. |
| `DomainAnalyzer:RdapBootstrapCacheHours` | How long RDAP bootstrap data is cached. |
| `RiskThresholds:SuspiciousMinScore` | Minimum structural risk score required to flag a domain as suspicious. |
| `RiskThresholds:*` | Per-signal scoring values for typosquatting, subdomain depth, hyphen abuse, entropy, keyword abuse, registration age/lifespan, WHOIS privacy, and character composition. |
| `ScanWorker:PerVariantDelayMs` | Delay between manual variant analyses to reduce external request pressure. |
| `ScanWorker:MaxConcurrentScans` | Maximum number of scans processed in parallel. |
| `FeedSources:OpenPhish:Url` | Source URL for the OpenPhish feed. |
| `FeedSources:OpenPhish:TimeoutSeconds` | Timeout for retrieving the OpenPhish feed. |
| `FeedIngestion:DeduplicationWindowHours` | Window used to skip domains that were recently scanned from feed ingestion. |
| `FeedIngestion:PollingIntervalHours` | How often feed ingestion runs. |
| `FeedIngestion:MaxDomainsPerCycle` | Maximum feed domains queued per ingestion cycle. |
| `FeedIngestion:StartupDelaySeconds` | Delay after app startup before the first feed ingestion cycle. |
| `Reports:HighRiskLookbackHours` | Default lookback window for `/Reports/Generate`. |

## Applying Migrations

Run migrations after pulling branches that add or change persisted models:

```powershell
dotnet ef database update --project .\SSA-Final\SSA-Final.csproj
```

The current scan-related tables are:

- `DomainScans`: one row per requested scan, including status, trigger, timestamps, and suspicious count.
- `DomainAnalysisResults`: one row per analyzed variant or direct feed domain, including suspicious status, classification, score summary, indicators, and reportable top-signal fields.

## Interpreting Scan Results

Scan status values:

- `Pending`: scan has been queued but not picked up.
- `InProgress`: background worker is processing the scan.
- `Completed`: all available variants or direct feed domains were analyzed.
- `Failed`: an exception prevented the scan from completing.

Variant result fields:

- `IsSuspicious`: true when network indicators are present or the structural risk score meets `RiskThresholds:SuspiciousMinScore`.
- `RiskClassification`: `Low`, `Medium`, `High`, or `Critical` based on the 0-100 risk score.
- `OverallRiskScore`: additive score capped at 100.
- `Indicators`: human-readable findings from structural, blocklist, SSL, redirect, and HTML checks.
- `TopRiskSignal`: highest-scoring structural or blocklist signal captured for reporting.
- `IsBlocklistMatch`: true when the domain matched the configured phishing feed.

High-risk reports:

- JSON: `GET /Reports/Generate`
- CSV: `GET /Reports/Generate?format=csv`
- Custom lookback: `GET /Reports/Generate?lookbackHours=48`

Reports include completed scans in the lookback window where `NumMaliciousDomains > 0`.

## Analyst Playbook

1. Start with `RiskClassification` and `OverallRiskScore`.
2. Review `Indicators` and `TopRiskSignal` to understand why the domain was flagged.
3. Treat `IsBlocklistMatch = true` as high-confidence evidence, then verify the source and timestamp before external escalation.
4. For structural-only findings, inspect whether the domain is imitating a known brand, hiding behind excessive subdomains, abusing hyphens/security keywords, or showing high entropy.
5. If a domain is likely malicious, capture the scan ID, discovered domain, indicators, screenshots if available, and report JSON/CSV row.
6. Escalate to stakeholders when a flagged domain targets a protected brand, collects credentials, appears in a blocklist, or has multiple high-confidence signals.
7. If a domain is a false positive, document the reason and consider adding only high-confidence, human-reviewed apex domains to `Legitimate_Domains.txt`.
8. Avoid adding broad hosting providers, URL shorteners, parked-domain services, or unknown customer subdomains to the legitimate allow-list.

## Known Limitations

- `Legitimate_Domains.txt` is an allow-list. A domain in that file bypasses structural scoring, so additions should be reviewed carefully.
- RDAP/WHOIS availability varies by TLD and registrar; lookup failures are recorded but not treated as malicious evidence by themselves.
- Some phishing infrastructure uses legitimate hosting providers, CDNs, and compromised sites; a clean hosting domain does not make the full URL safe.
- The analyzer focuses on domain and lightweight page signals. It does not sandbox JavaScript, submit forms, inspect screenshots, or follow complex redirect chains.
- Historical rows created before reportable risk fields were added may not have `TopRiskSignal`, `OverallRiskScore`, or blocklist metadata populated.
- Feed ingestion depends on external feed availability and local cache freshness.

## Demo Review Checklist

- Architecture diagram reviewed by: ____________________
- Operations handoff reviewed by: ____________________
- Review date: ____________________
- Notes: ____________________
