using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HybridTracker.Api.Models
{
    public class Application
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string CandidateName { get; set; } = null!;

        [Required]
        public string RoleApplied { get; set; } = null!; // Technical / Non-Technical

        [Required]
        public string Status { get; set; } = "Submitted"; // Default: Submitted

        public string? Comments { get; set; }

        // Foreign key to User
        [Required]
        public int UserId { get; set; }

        [ForeignKey("UserId")]
        public User? User { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
}
