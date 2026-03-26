using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SSA_Final.Data;
var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("SSA_FinalContextConnection") ?? throw new InvalidOperationException("Connection string 'SSA_FinalContextConnection' not found.");;

builder.Services.AddDbContext<SSA_FinalContext>(options => options.UseSqlServer(connectionString));

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false).AddEntityFrameworkStores<SSA_FinalContext>();

// Add services to the container.
builder.Services.AddControllersWithViews();

// Required for Core Identity to work
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
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

// Also required for Core Identity to work
app.MapRazorPages();

app.Run();
