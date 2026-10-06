using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class LoginViewModel // !!! дані передаються на вью як модель, а не рядками поокремо
    {
        [Required(ErrorMessage = "Введіть логін")]
        [Display(Name = "Логін")]
        public string Username { get; set; } = null!;

        [Required(ErrorMessage = "Введіть пароль")]
        [DataType(DataType.Password)]
        [Display(Name = "Пароль")]
        public string Password { get; set; } = null!;

        [Display(Name = "Запам'ятати мене")]
        public bool RememberMe { get; set; } = false;

        // приховане поле для returnUrl (не обов'язково виводити в UI)
        public string? ReturnUrl { get; set; }
    }
}