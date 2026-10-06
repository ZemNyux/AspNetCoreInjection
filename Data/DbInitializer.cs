using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Models;

namespace WebApplication1.Data
{
    public static class DbInitializer
    {
        public static async Task InitializeAsync(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

            // для розробки: видаляємо і створюємо базу
            await context.Database.EnsureDeletedAsync();
            await context.Database.EnsureCreatedAsync();

            await SeedUsersAsync(userManager);
            await SeedOrdersAsync(context, userManager);
        }

        private static async Task SeedUsersAsync(UserManager<IdentityUser> userManager)
        {
            if (await userManager.Users.AnyAsync())
                return;

            var users = new[]
            {
                new { UserName = "Alex", Email = "oleksandr@gmail.com", Password = "Alex!#$1234_" },
                new { UserName = "Oleg", Email = "olezhka@ukr.net", Password = "Oleg!#$1234_" },
                new { UserName = "admin", Email = "admin@example.com", Password = "Admin!#$1234_" } // ← для демо запиту #5
            };

            foreach (var userData in users)
            {
                var user = new IdentityUser
                {
                    UserName = userData.UserName,
                    Email = userData.Email,
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(user, userData.Password);
                if (!result.Succeeded)
                {
                    throw new Exception($"Не вдалося створити користувача {userData.UserName}: " +
                        string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
        }

        private static async Task SeedOrdersAsync(
            ApplicationDbContext context,
            UserManager<IdentityUser> userManager)
        {
            if (await context.Orders.AnyAsync())
                return;

            var alex = await userManager.FindByNameAsync("Alex");
            var oleg = await userManager.FindByNameAsync("Oleg");
            var admin = await userManager.FindByNameAsync("admin");

            if (alex == null || oleg == null || admin == null)
                throw new Exception("Користувачі не знайдені для прив'язки замовлень");

            var orders = new[]
            {
                new Order
                {
                    UserId = alex.Id,
                    ProductName = "Комплюктер",
                    Price = 25000,
                    Address = "Одеса"
                },
                new Order
                {
                    UserId = oleg.Id,
                    ProductName = "Айфон 17",
                    Price = 69999,
                    Address = "Львів"
                },
                new Order
                {
                    UserId = admin.Id,
                    ProductName = "Сервер Dell PowerEdge",
                    Price = 150000,
                    Address = "Київ, серверна кімната"
                }
            };

            context.Orders.AddRange(orders);
            await context.SaveChangesAsync();
        }
    }
}