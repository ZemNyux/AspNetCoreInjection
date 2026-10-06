using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Models;

namespace WebApplication1.Controllers
{
    public class OrdersController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;

        public OrdersController(ApplicationDbContext db, UserManager<IdentityUser> userManager)
        {
            _db = db;
            _userManager = userManager;
        }

        [Authorize]
        public async Task<IActionResult> Details(int id)
        {
            var order = await _db.Orders.FindAsync(id);
            if (order == null) return NotFound();

            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser == null) return Challenge();

            if (order.UserId != currentUser.Id)
                return Forbid();

            return View(order);
        }

        // порушення: метод відкритий для всіх без авторизації
        // це дозволяє будь-кому викликати sql-запити напряму
        // виправлення: прибрати AllowAnonymous і фільтрувати дані по поточному користувачу
        [HttpGet]
        [AllowAnonymous]  // критично: доступ без логіну
        public async Task<IActionResult> Search(string? filter = null)
        {
            List<Order> orders = new List<Order>();
            string injectionType = "none";

            if (!string.IsNullOrEmpty(filter))
            {
                try
                {
                    // порушення: програма аналізує payload замість того, щоб його блокувати
                    // filter використовується як частина sql-команди
                    if (filter.Contains("DROP TABLE", StringComparison.OrdinalIgnoreCase))
                    {
                        // порушення: ExecuteSqlRaw + string interpolation
                        // користувацький ввід напряму вбудовується в sql
                        // це дозволяє виконувати drop table / delete / update
                        // виправлення: ніколи не виконувати raw sql з input користувача
                        await _db.Database.ExecuteSqlRawAsync(
                            $"SELECT * FROM Orders WHERE UserId LIKE '%{filter}%'"
                        );

                        injectionType = "drop_table";
                        ViewBag.DropTableSuccess = true;
                    }
                    else
                    {
                        // порушення: класична sql injection через LIKE '%{filter}%'
                        // filter приходить з query string і без валідації вбудовується в sql
                        // зловмисник може читати всі замовлення або змінити логіку запиту
                        var dangerousSql = $@"
                            SELECT * FROM Orders 
                            WHERE UserId LIKE '%{filter}%' 
                               OR ProductName LIKE '%{filter}%' 
                               OR Address LIKE '%{filter}%'";

                        // порушення: FromSqlRaw не параметризує запит автоматично
                        // у поєднанні з interpolation це пряма sql injection
                        orders = await _db.Orders
                            .FromSqlRaw(dangerousSql)
                            .ToListAsync();

                        injectionType = "data_leak";
                    }
                }
                catch (Exception ex)
                {
                    // порушення: логіка розрахована на успішний drop table
                    // код очікує атаку, а не захищається від неї, ну це понятно для прикладу, але все ж
                    if (filter.Contains("DROP TABLE", StringComparison.OrdinalIgnoreCase))
                    {
                        var dropHtml = $@"
                            <!DOCTYPE html>
                            <html lang=""uk"">
                            <head>
                                <meta charset=""UTF-8"">
                                <title>SQL Injection — DROP TABLE</title>
                                <style>
                                    body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 80px; background: #f8f9fa; }}
                                    h1 {{ color: #d9534f; font-size: 3.5em; }}
                                    .card {{ max-width: 700px; margin: 40px auto; padding: 30px; background: white; border-radius: 12px; box-shadow: 0 6px 30px rgba(0,0,0,0.15); }}
                                    .alert {{ background: #d9534f; color: white; padding: 20px; border-radius: 8px; font-size: 1.4em; margin-bottom: 30px; }}
                                    .btn {{ padding: 14px 32px; background: #337ab7; color: white; text-decoration: none; border-radius: 8px; font-size: 1.4em; display: inline-block; }}
                                    code {{ background: #333; color: #0f0; padding: 4px 8px; border-radius: 4px; }}
                                </style>
                            </head>
                            <body>
                                <h1>КРИТИЧНА SQL INJECTION!</h1>
                                <div class=""card"">
                                    <div class=""alert"">
                                        <strong>⚠️ ТАБЛИЦЮ ORDERS ВИДАЛЕНО! ⚠️</strong><br><br>
                                        Виконано команду: <code>{System.Net.WebUtility.HtmlEncode(filter)}</code><br><br>
                                        Вся база даних замовлень знищена!<br>
                                        Помилка: <code>{System.Net.WebUtility.HtmlEncode(ex.Message)}</code>
                                    </div>
                                    <p style=""font-size: 1.5em;"">Це найнебезпечніший тип SQL Injection — повна втрата даних!</p>
                                    <a href=""/"" class=""btn"">Повернутися на головну</a>
                                </div>
                            </body>
                            </html>";

                        return Content(dropHtml, "text/html; charset=utf-8");
                    }

                    // порушення: витік деталей помилки бази даних
                    // повідомлення допомагають зловмиснику підбирати payload
                    ViewBag.ErrorMessage = ex.Message;
                }
            }

            // порушення: результати пошуку не обмежені поточним користувачем
            // будь-хто може отримати всі замовлення з бази
            ViewBag.AppliedFilter = filter ?? "(немає)";
            ViewBag.IsInjectionDemo = !string.IsNullOrEmpty(filter);
            ViewBag.InjectionType = injectionType;

            return View(orders);
        }
    }
}