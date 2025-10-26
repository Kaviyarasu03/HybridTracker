using Microsoft.EntityFrameworkCore;
using HybridTracker.Api.Models;

namespace HybridTracker.Api.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> Users => Set<User>();
        public DbSet<Role> Roles => Set<Role>();
        public DbSet<Application> Applications => Set<Application>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Seed initial roles
            modelBuilder.Entity<Role>().HasData(
                new Role { Id = 1, Name = "Applicant" },
                new Role { Id = 2, Name = "BotMimic" },
                new Role { Id = 3, Name = "Admin" }
            );
        }
    }
}
 