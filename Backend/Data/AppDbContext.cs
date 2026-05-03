using Microsoft.EntityFrameworkCore;
using RsvpApi.Models;

namespace RsvpApi.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User>         Users        => Set<User>();
    public DbSet<RsvpEntry>    RsvpEntries  => Set<RsvpEntry>();
    public DbSet<SiteSettings> SiteSettings => Set<SiteSettings>();
}
