using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Models;

namespace WebApplication1.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _db;

        public AccountController(
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            ApplicationDbContext db)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
        }

        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View(new LoginViewModel { ReturnUrl = returnUrl });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            returnUrl = model.ReturnUrl ?? returnUrl;

            if (!ModelState.IsValid)
            {
                model.ReturnUrl = returnUrl;
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(
                model.Username!,
                model.Password!,
                model.RememberMe,
                lockoutOnFailure: true);

            if (result.Succeeded)
            {
                var user = await _userManager.FindByNameAsync(model.Username!);

                if (user != null)
                {
                    // порушення: sql формується через string interpolation
                    // дані (user.Id) підставляються прямо в запит без параметрів
                    // це класична причина sql injection
                    // виправлення: використовувати FromSqlInterpolated або параметри
                    var dangerousSql = $"SELECT TOP 1 * FROM Orders WHERE UserId = '{user.Id}' ORDER BY Id";

                    // порушення: FromSqlRaw виконує "сирий" sql без автоматичної параметризації
                    // у поєднанні з конкатенацією рядків це напряму відкриває sql injection
                    var order = await _db.Orders
                        .FromSqlRaw(dangerousSql)
                        .FirstOrDefaultAsync();

                    if (order != null)
                    {
                        return RedirectToAction("Details", "Orders", new { id = order.Id });
                    }
                }

                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    return LocalRedirect(returnUrl);

                return RedirectToAction("Login", "Account");
            }

            if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "Акаунт заблоковано через багато невдалих спроб.");
                return View(model);
            }

            ModelState.AddModelError("", "Невірний логін або пароль");
            model.ReturnUrl = returnUrl;
            return View(model);
        }

        [HttpPost]
        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }

        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }

        // порушення: метод доступний без авторизації
        // будь-хто може передавати довільний userId у query string
        // виправлення: прибрати AllowAnonymous і брати userId з User.Identity
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> RedirectToUserOrder(string? userId = null)
        {
            try
            {
                // порушення: логіка програми очікує sql injection замість того, щоб його блокувати
                // userId використовується як sql payload, а не як ідентифікатор
                if (!string.IsNullOrEmpty(userId) && userId.Contains("UPDATE Orders SET Price"))
                {
                    // порушення: ExecuteSqlRaw виконує sql, зібраний з користувацького вводу
                    // це дозволяє виконувати update/delete/drop
                    // виправлення: ніколи не виконувати raw sql з input користувача
                    await _db.Database.ExecuteSqlRawAsync(
                        $"SELECT * FROM Orders WHERE UserId = '{userId}'"
                    );

                    var updateHtml = GenerateSuccessHtml(
                        "МОДИФІКАЦІЯ ДАНИХ",
                        $"Всі ціни в замовленнях змінено на <strong>1 грн</strong> — навіть без логіну!",
                        userId
                    );
                    return Content(updateHtml, "text/html; charset=utf-8");
                }

                // порушення: та сама sql injection, але вже з таблицею користувачів
                // потенційно дозволяє змінювати паролі та ролі
                if (!string.IsNullOrEmpty(userId) && userId.Contains("UPDATE AspNetUsers"))
                {
                    var passwordHasher = new PasswordHasher<IdentityUser>();
                    var dummyUser = new IdentityUser();
                    var newPasswordHash = passwordHasher.HashPassword(dummyUser, "Hacked123!");

                    var adminUser = await _userManager.FindByNameAsync("admin");
                    if (adminUser != null)
                    {
                        await _db.Database.ExecuteSqlRawAsync(
                            $"UPDATE AspNetUsers SET PasswordHash = '{newPasswordHash}' WHERE UserName = 'admin'"
                        );
                    }

                    var updateUserHtml = GenerateSuccessHtml(
                        "ЗМІНА ПАРОЛЮ АДМІНІСТРАТОРА",
                        $"Пароль адміністратора було змінено через SQL Injection!<br>" +
                        $"Зловмисник тепер може увійти під обліковим записом адміна.",
                        userId
                    );
                    return Content(updateUserHtml, "text/html; charset=utf-8");
                }

                // порушення: userId береться напряму з query string без валідації
                // виправлення: ідентифікатор користувача не повинен приходити ззовні
                string targetUserId = string.IsNullOrEmpty(userId)
                    ? "00000000-0000-0000-0000-000000000000"
                    : userId;

                // порушення: знову конкатенація sql з користувацьким введенням
                // це дозволяє читати чужі дані через sql injection
                var dangerousSql = $"SELECT TOP 1 * FROM Orders WHERE UserId = '{targetUserId}' ORDER BY Id";

                var order = await _db.Orders
                    .FromSqlRaw(dangerousSql)
                    .FirstOrDefaultAsync();

                if (order != null)
                {
                    // порушення: відсутня перевірка, що замовлення належить поточному користувачу
                    // виправлення: перевіряти order.UserId == User.Identity.Id
                    var readHtml = $@"
                        <!DOCTYPE html>
                        <html lang=""uk"">
                        <head>
                            <meta charset=""UTF-8"">
                            <title>SQL Injection — Витік даних</title>
                            <style>
                                body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 80px; background: #f8f9fa; }}
                                h1 {{ color: #d9534f; font-size: 3em; }}
                                .card {{ max-width: 600px; margin: 40px auto; padding: 30px; background: white; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
                                .alert {{ background: #f2dede; color: #a94442; padding: 20px; border-radius: 8px; margin-bottom: 30px; font-size: 1.3em; }}
                                ul {{ text-align: left; font-size: 1.4em; }}
                                .btn {{ padding: 14px 30px; background: #337ab7; color: white; text-decoration: none; border-radius: 8px; font-size: 1.3em; margin-top: 30px; display: inline-block; }}
                            </style>
                        </head>
                        <body>
                            <h1>УСПІШНА SQL INJECTION!</h1>
                            <div class=""card"">
                                <div class=""alert"">
                                    <strong>УВАГА:</strong> Отримано доступ до чужого замовлення <strong>без авторизації</strong>!<br>
                                    Payload: <code>{System.Net.WebUtility.HtmlEncode(userId ?? "(немає)")}</code>
                                </div>
                                <h2>Деталі вкраденого замовлення:</h2>
                                <ul>
                                    <li><strong>ID:</strong> {order.Id}</li>
                                    <li><strong>Товар:</strong> {order.ProductName}</li>
                                    <li><strong>Ціна:</strong> {order.Price} грн</li>
                                    <li><strong>Адреса:</strong> {order.Address}</li>
                                    <li><strong>Власник (UserId):</strong> {order.UserId}</li>
                                </ul>
                                <a href=""/Account/Login"" class=""btn"">Перейти на логін</a>
                            </div>
                        </body>
                        </html>";

                    return Content(readHtml, "text/html; charset=utf-8");
                }
            }
            catch (Exception ex)
            {
                // порушення: повернення користувачу деталей sql/exception
                // це допомагає зловмиснику підбирати payload
                // виправлення: логувати помилку, але показувати загальне недеталізоване повідомлення
                var errorHtml = GenerateSuccessHtml(
                    "ПОМИЛКА ВИКОНАННЯ",
                    $"SQL запит виконано, але виникла помилка: <code>{System.Net.WebUtility.HtmlEncode(ex.Message)}</code>",
                    userId ?? "немає"
                );
                return Content(errorHtml, "text/html; charset=utf-8");
            }

            return RedirectToAction("Login");
        }

        private string GenerateSuccessHtml(string title, string message, string payload)
        {
            return $@"
                <!DOCTYPE html>
                <html lang=""uk"">
                <head>
                    <meta charset=""UTF-8"">
                    <title>SQL Injection — {title}</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 80px; background: #f8f9fa; }}
                        h1 {{ color: #d9534f; font-size: 3.5em; }}
                        .card {{ max-width: 700px; margin: 40px auto; padding: 30px; background: white; border-radius: 12px; box-shadow: 0 6px 30px rgba(0,0,0,0.15); }}
                        .alert {{ background: #f2dede; color: #a94442; padding: 20px; border-radius: 8px; font-size: 1.4em; margin-bottom: 30px; }}
                        .btn {{ padding: 14px 32px; background: #337ab7; color: white; text-decoration: none; border-radius: 8px; font-size: 1.4em; display: inline-block; }}
                        code {{ background: #f5f5f5; padding: 4px 8px; border-radius: 4px; font-size: 0.9em; }}
                    </style>
                </head>
                <body>
                    <h1>УСПІШНА SQL INJECTION!</h1>
                    <div class=""card"">
                        <div class=""alert"">
                            <strong>НЕБЕЗПЕКА!</strong> {message}<br>
                            Payload: <code>{System.Net.WebUtility.HtmlEncode(payload)}</code>
                        </div>
                        <p style=""font-size: 1.5em;"">Це показує, як зловмисник міг би повністю змінити або видалити дані в базі.</p>
                        <a href=""/Account/Login"" class=""btn"">Перейти на логін</a>
                    </div>
                </body>
                </html>";
        }
    }
}