using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using HybridTracker.Api.Data;
using HybridTracker.Api.Models;

namespace HybridTracker.Api.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class ApplicationsController : ControllerBase
    {
        private readonly AppDbContext _context;

        public ApplicationsController(AppDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        // POST: api/applications
        [HttpPost]
        public async Task<IActionResult> CreateApplication([FromBody] Application application)
        {
            if (application == null)
                return BadRequest(new { message = "Application data is required" });

            var user = await _context.Users.FindAsync(application.UserId);
            if (user == null)
                return BadRequest(new { message = "Invalid UserId" });

            // Default status if not provided
            if (string.IsNullOrEmpty(application.Status))
                application.Status = "Submitted";

            _context.Applications.Add(application);
            await _context.SaveChangesAsync();

            return Ok(new
            {
                application.Id,
                application.CandidateName,
                application.RoleApplied,
                application.Status,
                application.Comments,
                User = new { user.Id, user.Username, user.Email }
            });
        }

        // GET: api/applications/user/{userId}
        [HttpGet("user/{userId}")]
        public async Task<IActionResult> GetUserApplications(int userId)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null) return NotFound(new { message = "User not found" });

            var applications = await _context.Applications
                .Where(a => a.UserId == userId)
                .Select(a => new
                {
                    a.Id,
                    a.CandidateName,
                    a.RoleApplied,
                    a.Status,
                    a.Comments
                })
                .ToListAsync();

            return Ok(new { User = new { user.Id, user.Username, user.Email }, Applications = applications });
        }

        // GET: api/applications
        [HttpGet]
        [Authorize(Roles = "Admin,BotMimic")] // Only Admin or BotMimic can view all applications
        public async Task<IActionResult> GetAllApplications()
        {
            var applications = await _context.Applications
                .Include(a => a.User)
                .Select(a => new
                {
                    a.Id,
                    a.CandidateName,
                    a.RoleApplied,
                    a.Status,
                    a.Comments,
                    User = new { a.User.Id, a.User.Username, a.User.Email }
                })
                .ToListAsync();

            return Ok(applications);
        }
    }
}
