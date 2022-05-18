using System.ComponentModel.DataAnnotations;

namespace CleanArchMvc.API.Models
{
    public class Register
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Passoword", ErrorMessage = "Passwords don't match")]
        public string ConfirmPassword { get; set; }

    }
}
