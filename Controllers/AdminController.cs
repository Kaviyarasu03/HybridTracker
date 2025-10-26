using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using HybridTracker.Api.Data;
using HybridTracker.Api.Models;

namespace HybridTracker.Api.Controllers
{
    [Authorize(Roles = "Admin")] // Only Admin can access
    [Route("api/admin")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        private readonly AppDbContext _context;

        public AdminController(AppDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        // POST: api/admin/update-application
        [HttpPost("update-application")]
        public async Task<IActionResult> UpdateNonTechnicalApplication([FromBody] Application updatedApp)
        {
            if (updatedApp == null)
                return BadRequest(new { message = "Application data required" });

            var app = await _context.Applications.FindAsync(updatedApp.Id);
            if (app == null)
                return NotFound(new { message = "Application not found" });

            // Only allow non-technical applications
            if (app.RoleApplied.ToLower() == "technical")
                return BadRequest(new { message = "Bot Mimic handles technical roles" });

            app.Status = string.IsNullOrEmpty(updatedApp.Status) ? app.Status : updatedApp.Status;
            app.Comments = string.IsNullOrEmpty(updatedApp.Comments) ? app.Comments : updatedApp.Comments;

            await _context.SaveChangesAsync();

            return Ok(new
            {
                message = "Non-technical application updated successfully",
                application = new
                {
                    app.Id,
                    app.CandidateName,
                    app.RoleApplied,
                    app.Status,
                    app.Comments
                }
            });
        }

        // GET: api/admin/applications
        [HttpGet("applications")]
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
