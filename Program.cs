using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Data;
using WebApplication1.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 8;
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireLowercase = true;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    await DbInitializer.InitializeAsync(app.Services);
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// налаштування маршрутів для прикладу
app.MapControllerRoute(
    name: "orders_search",
    pattern: "Orders/search",
    defaults: new { controller = "Orders", action = "Search" });

app.MapControllerRoute(
    name: "account_redirect",
    pattern: "Account/RedirectToUserOrder",
    defaults: new { controller = "Account", action = "RedirectToUserOrder" });

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

app.Run();

// ДЕМО SQL-INJECTION ЗАПИТІВ (навіть не треба логінитися), запускати по черзі:
// 
// 1. ВИТІК ДАНИХ — повертає перше замовлення з бази
// https://localhost:7093/Account/RedirectToUserOrder?userId=' OR '1'='1
// 
// 2. МАСОВИЙ ВИТІК — виводить усі замовлення з бази
// https://localhost:7093/Orders/search?filter=' OR '1'='1
// 
// 3. МОДИФІКАЦІЯ ДАНИХ — змінює ціну всіх замовлень на 1 грн
// https://localhost:7093/Account/RedirectToUserOrder?userId=abc'; UPDATE Orders SET Price = 1 --
// https://localhost:7093/Orders/search?filter=' OR '1'='1
// 
// 4. ВИДАЛЕННЯ ТАБЛИЦІ — DROP TABLE Orders (валимо сайт остаточно, багато чого зав'язано на цій таблиці)
// https://localhost:7093/Orders/search?filter='; DROP TABLE Orders --