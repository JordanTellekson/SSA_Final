using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SSA_Final.Data;
using SSA_Final.Interfaces;
using SSA_Final.Services;

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

builder.Services.AddScoped<IDomainGenerator, DomainGeneratorService>();
builder.Services.AddScoped<IDomainAnalyzer, DomainAnalyzerService>();
builder.Services.AddScoped<IDomainRiskAnalyzer, DomainRiskAnalyzerService>();
builder.Services.AddSingleton<IScanStore, ScanStoreService>();
builder.Services.AddTransient<ISslCertificateChecker, SslCertificateChecker>();

var timeoutSeconds = builder.Configuration.GetValue<int>("DomainAnalyzer:TimeoutSeconds");
var timeoutSpan = TimeSpan.FromSeconds(timeoutSeconds > 0 ? timeoutSeconds : 5);

// 1. NoRedirect Client
builder.Services.AddHttpClient("DomainAnalyzer.NoRedirect", client => {
    client.Timeout = timeoutSpan;
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    AllowAutoRedirect = false,
    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
});

// 2. Follow Client
builder.Services.AddHttpClient("DomainAnalyzer.Follow", client => {
    client.Timeout = timeoutSpan;
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    AllowAutoRedirect = true,
    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
});

logger.LogInformation("Registered IDomainGenerator -> DomainGeneratorService (Scoped).");
logger.LogInformation("Registered IDomainAnalyzer  -> DomainAnalyzerService (Scoped).");
logger.LogInformation("Registered IDomainRiskAnalyzer -> DomainRiskAnalyzerService (Scoped).");
logger.LogInformation("Registered IScanStore -> ScanStoreService (Singleton).");
logger.LogInformation("Registered ISslCertificateChecker -> SslCertificateChecker (Transient).");
logger.LogInformation("Registered named HttpClients: DomainAnalyzer.NoRedirect, DomainAnalyzer.Follow.");

// Configure Identity
builder.Services.AddDefaultIdentity<IdentityUser>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
}).AddEntityFrameworkStores<SSA_FinalContext>();

// Add services to the container
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

var app = builder.Build();

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