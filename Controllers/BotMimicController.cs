using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using HybridTracker.Api.Data;
using HybridTracker.Api.Models;

namespace HybridTracker.Api.Controllers
{
    [Route("api/bot")]
    [ApiController]
    public class BotMimicController : ControllerBase
    {
        private readonly AppDbContext _context;

        public BotMimicController(AppDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        // POST: api/bot/update-status
        [HttpPost("update-status")]
        public async Task<IActionResult> UpdateTechnicalApplications()
        {
            // Get all technical applications in non-final status
            var applications = await _context.Applications
                .Include(a => a.User)
                .Where(a => a.RoleApplied.ToLower() == "technical" && a.Status != "Offer")
                .ToListAsync();

            foreach (var app in applications)
            {
                // Simple workflow progression
                app.Status = app.Status switch
                {
                    "Submitted" => "Reviewed",
                    "Reviewed" => "Interview",
                    "Interview" => "Offer",
                    _ => app.Status
                };

                if (string.IsNullOrEmpty(app.Comments))
                    app.Comments = "Updated by Bot Mimic";

                else
                    app.Comments += " | Updated by Bot Mimic";
            }

            await _context.SaveChangesAsync();

            return Ok(new
            {
                message = "Technical applications updated successfully",
                updatedCount = applications.Count
            });
        }
    }
}
