using System.ComponentModel.DataAnnotations;

namespace HybridTracker.Api.Models
{
    public class UserRegisterRequest
    {
        [Required(ErrorMessage = "Username is required")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "RoleId is required")]
        public int RoleId { get; set; } = 1; // Default to Applicant
    }
}
