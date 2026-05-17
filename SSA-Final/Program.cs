// Application bootstrap and dependency wiring for the SSA_Final web app.
// Configures logging, database access, dependency injection, HTTP clients,
// authentication, middleware, and endpoint routing.

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SSA_Final.Data;
using SSA_Final.Interfaces;
using SSA_Final.Services;
using System.Threading.Channels;

var builder = WebApplication.CreateBuilder(args);

// Configure logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();
builder.Logging.SetMinimumLevel(LogLevel.Information);

var logger = LoggerFactory.Create(config =>
{
    config.AddConsole();
    config.AddDebug();
}).CreateLogger("Program");

logger.LogInformation("Starting SSA_Final web application.");

// Configure database
var connectionString = builder.Configuration.GetConnectionString("SSA_FinalContextConnection")
    ?? throw new InvalidOperationException("Connection string 'SSA_FinalContextConnection' not found.");
builder.Services.AddDbContext<SSA_FinalContext>(options =>
{
    options.UseSqlServer(connectionString);
});

logger.LogInformation("Database context configured with connection string.");

builder.Services.AddMemoryCache();
builder.Services.AddHttpClient();

builder.Services.AddSingleton<ISearchService, SearchService>();
builder.Services.AddScoped<IDomainGenerator, DomainGeneratorService>();
builder.Services.AddScoped<IDomainAnalyzer, DomainAnalyzerService>();
builder.Services.AddScoped<IPhishingBlocklistService, PhishingBlocklistService>();
builder.Services.AddScoped<IDomainRegistrationLookupService, RdapDomainRegistrationLookupService>();
builder.Services.AddScoped<IScanStore, SqlScanStoreService>();
builder.Services.AddScoped<IReportService, ReportService>();
builder.Services.AddTransient<ISslCertificateChecker, SslCertificateChecker>();

// Scan background job infrastructure: register an unbounded channel and expose both
// ends separately so the controller only writes and the background service only reads.
var scanChannel = Channel.CreateUnbounded<Guid>(new UnboundedChannelOptions
{
    SingleReader = true,   // Only ScanBackgroundService reads.
    SingleWriter = false   // Multiple HTTP requests may write concurrently.
});
builder.Services.AddSingleton(scanChannel.Writer);
builder.Services.AddSingleton(scanChannel.Reader);
builder.Services.AddHostedService<ScanBackgroundService>();
if (builder.Configuration.GetValue("CertStream:Enabled", true))
{
    builder.Services.AddHostedService<CertStreamIngestionBackgroundService>();
}

builder.Services.AddHostedService<ScheduledScanBackgroundService>();

builder.Services.AddSingleton<IDomainFeedSource, OpenPhishFeedSource>();
builder.Services.AddHostedService<FeedIngestionBackgroundService>();

var timeoutSeconds = builder.Configuration.GetValue<int>("DomainAnalyzer:TimeoutSeconds");
var timeoutSpan = TimeSpan.FromSeconds(timeoutSeconds > 0 ? timeoutSeconds : 5);
var rdapTimeoutSeconds = builder.Configuration.GetValue<int>("DomainAnalyzer:RdapTimeoutSeconds");
var rdapTimeoutSpan = TimeSpan.FromSeconds(rdapTimeoutSeconds > 0 ? rdapTimeoutSeconds : 3);

var blocklistTimeoutSeconds = builder.Configuration.GetValue<int>("PhishingBlocklists:OpenPhish:TimeoutSeconds");
var blocklistTimeoutSpan = TimeSpan.FromSeconds(blocklistTimeoutSeconds > 0 ? blocklistTimeoutSeconds : 30);
builder.Services.AddHttpClient(PhishingBlocklistService.HttpClientName, client =>
{
    client.Timeout = blocklistTimeoutSpan;
});

var feedSourceTimeoutSeconds = builder.Configuration.GetValue<int>("FeedSources:OpenPhish:TimeoutSeconds");
var feedSourceTimeoutSpan = TimeSpan.FromSeconds(feedSourceTimeoutSeconds > 0 ? feedSourceTimeoutSeconds : 30);
builder.Services.AddHttpClient(OpenPhishFeedSource.HttpClientName, client =>
{
    client.Timeout = feedSourceTimeoutSpan;
});

// In development, the DangerousAcceptAnyServerCertificateValidator bypass is intentionally
// enabled so the analyzer can reach domains with self-signed or expired certificates —
// a common indicator on phishing sites. In all other environments (staging, production, demo)
// the default OS-level certificate validation is used to prevent a known security weakness
// from being present in assessed builds.
bool isDevelopment = builder.Environment.IsDevelopment();

// 1. NoRedirect Client
builder.Services.AddHttpClient("DomainAnalyzer.NoRedirect", client => {
    client.Timeout = timeoutSpan;
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    AllowAutoRedirect = false,
    ServerCertificateCustomValidationCallback = isDevelopment
        ? HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        : null
});

// 2. Follow Client
builder.Services.AddHttpClient("DomainAnalyzer.Follow", client => {
    client.Timeout = timeoutSpan;
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    AllowAutoRedirect = true,
    ServerCertificateCustomValidationCallback = isDevelopment
        ? HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        : null
});

// 3. RDAP Client
builder.Services.AddHttpClient("DomainAnalyzer.Rdap", client => {
    client.Timeout = rdapTimeoutSpan;
});

logger.LogInformation("Registered ISearchService -> SearchService (Singleton).");
logger.LogInformation("Registered IDomainGenerator -> DomainGeneratorService (Scoped).");
logger.LogInformation("Registered IDomainAnalyzer  -> DomainAnalyzerService (Scoped).");
logger.LogInformation("Registered IScanStore -> SqlScanStoreService (Scoped).");
logger.LogInformation("Registered IReportService -> ReportService (Scoped).");
logger.LogInformation("Registered ISslCertificateChecker -> SslCertificateChecker (Transient).");
logger.LogInformation("Registered IDomainRegistrationLookupService -> RdapDomainRegistrationLookupService (Scoped).");
logger.LogInformation("Registered named HttpClients: DomainAnalyzer.NoRedirect, DomainAnalyzer.Follow, DomainAnalyzer.Rdap, Blocklist.OpenPhish, FeedSource.OpenPhish.");
logger.LogInformation("Registered Channel<Guid> scan queue (ChannelWriter/ChannelReader as Singletons).");
logger.LogInformation("Registered ScanBackgroundService (IHostedService).");
logger.LogInformation("Registered CertStreamIngestionBackgroundService (IHostedService) when CertStream:Enabled is true.");
logger.LogInformation("Registered ScheduledScanBackgroundService (IHostedService).");
logger.LogInformation("Registered IDomainFeedSource -> OpenPhishFeedSource (Singleton).");
logger.LogInformation("Registered FeedIngestionBackgroundService (IHostedService).");

// Configure Identity
builder.Services.AddDefaultIdentity<IdentityUser>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
}).AddEntityFrameworkStores<SSA_FinalContext>();

// Add services to the container
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

var app = builder.Build();

var applyMigrationsOnStartup = builder.Configuration.GetValue("Database:ApplyMigrationsOnStartup", true);
if (applyMigrationsOnStartup)
{
    using var scope = app.Services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<SSA_FinalContext>();

    logger.LogInformation("Applying database migrations.");
    await dbContext.Database.MigrateAsync();
    logger.LogInformation("Database migrations applied.");
}
else
{
    logger.LogInformation("Database migration on startup is disabled.");
}

// Middleware: global exception logging
app.Use(async (context, next) =>
{
    try
    {
        await next.Invoke();
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Unhandled exception occurred while processing request: {Path}", context.Request.Path);
        throw;
    }
});

// Configure HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.MapRazorPages();

logger.LogInformation("Application configured and ready to run.");
app.Run();

