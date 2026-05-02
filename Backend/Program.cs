using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using RsvpApi.Data;
using RsvpApi.Dtos;
using RsvpApi.Models;

var builder = WebApplication.CreateBuilder(args);

var port = Environment.GetEnvironmentVariable("PORT") ?? "5050";
builder.WebHost.UseUrls($"http://+:{port}");

// ── Config ────────────────────────────────────────────────
var adminPassword = builder.Configuration["AdminPassword"] ?? "admin";
var allowedOrigin = builder.Configuration["AllowedOrigin"] ?? "*";

// ── Database ──────────────────────────────────────────────
builder.Services.AddDbContext<AppDbContext>(opt =>
    opt.UseSqlite("Data Source=rsvp.db"));

// ── CORS: restrict to your domain in production ───────────
builder.Services.AddCors(opt =>
    opt.AddDefaultPolicy(p =>
    {
        if (allowedOrigin == "*")
            p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
        else
            p.WithOrigins(allowedOrigin).AllowAnyHeader().AllowAnyMethod();
    }));

// ── Rate limiting ─────────────────────────────────────────
builder.Services.AddRateLimiter(opt =>
{
    opt.RejectionStatusCode = 429;

    // Public RSVP submit: 5 per IP per 10 minutes
    opt.AddPolicy("rsvp-submit", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit      = 5,
                Window           = TimeSpan.FromMinutes(10),
                QueueLimit       = 0
            }));

    // Admin endpoints: 30 per IP per minute (brute-force protection)
    opt.AddPolicy("admin", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit      = 30,
                Window           = TimeSpan.FromMinutes(1),
                QueueLimit       = 0
            }));
});

var app = builder.Build();

// ── Create DB on startup ──────────────────────────────────
using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreated();

// ── Security headers ──────────────────────────────────────
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"]  = "nosniff";
    ctx.Response.Headers["X-Frame-Options"]          = "DENY";
    ctx.Response.Headers["Referrer-Policy"]          = "strict-origin-when-cross-origin";
    ctx.Response.Headers["Permissions-Policy"]       = "geolocation=(), camera=(), microphone=()";
    ctx.Response.Headers["Content-Security-Policy"]  =
        "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://maps.google.com; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "frame-src https://maps.google.com; " +
        "img-src 'self' data: https:;";
    await next();
});

app.UseCors();
app.UseRateLimiter();

// ── Static files from wwwroot (index.html, admin.html, images/) ──
app.UseDefaultFiles();
app.UseStaticFiles();

// ── Helpers ───────────────────────────────────────────────
bool IsAdmin(HttpContext ctx) =>
    ctx.Request.Headers.TryGetValue("X-Admin-Password", out var val) &&
    val == adminPassword;

static string Sanitize(string s) =>
    s.Trim().Replace("<", "").Replace(">", "").Replace("\"", "");

static bool IsValidPhone(string p) =>
    System.Text.RegularExpressions.Regex.IsMatch(p, @"^[\d\-\+\s]{7,15}$");

// ── API Endpoints ─────────────────────────────────────────

// POST /api/rsvp
app.MapPost("/api/rsvp", async (SubmitRsvpRequest req, AppDbContext db) =>
{
    if (string.IsNullOrWhiteSpace(req.FirstName) ||
        string.IsNullOrWhiteSpace(req.LastName)  ||
        string.IsNullOrWhiteSpace(req.Phone))
        return Results.BadRequest(new { error = "שדות חובה חסרים" });

    if (req.FirstName.Length > 50 || req.LastName.Length > 50)
        return Results.BadRequest(new { error = "שם ארוך מדי" });

    if (!IsValidPhone(req.Phone))
        return Results.BadRequest(new { error = "מספר פלאפון לא תקין" });

    if (req.Guests is < 1 or > 20)
        return Results.BadRequest(new { error = "מספר אורחים לא תקין" });

    var entry = new RsvpEntry
    {
        FirstName = Sanitize(req.FirstName),
        LastName  = Sanitize(req.LastName),
        Phone     = Sanitize(req.Phone),
        Guests    = req.Attending ? req.Guests : 0,
        Attending = req.Attending,
        CreatedAt = DateTime.UtcNow
    };

    db.RsvpEntries.Add(entry);
    await db.SaveChangesAsync();

    return Results.Created($"/api/rsvp/{entry.Id}", ToResponse(entry));
}).RequireRateLimiting("rsvp-submit");

// GET /api/rsvp  (admin)
app.MapGet("/api/rsvp", async (HttpContext ctx, AppDbContext db, string? q) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();

    var query = db.RsvpEntries.AsQueryable();

    if (!string.IsNullOrWhiteSpace(q))
    {
        var term = q.Trim().ToLower();
        query = query.Where(e =>
            e.FirstName.ToLower().Contains(term) ||
            e.LastName.ToLower().Contains(term)  ||
            e.Phone.Contains(term));
    }

    var list = (await query.OrderByDescending(e => e.CreatedAt).ToListAsync())
               .Select(ToResponse);

    return Results.Ok(list);
}).RequireRateLimiting("admin");

// GET /api/rsvp/stats  (admin)
app.MapGet("/api/rsvp/stats", async (HttpContext ctx, AppDbContext db) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();

    var all         = await db.RsvpEntries.ToListAsync();
    var attending   = all.Where(e => e.Attending).ToList();

    return Results.Ok(new StatsResponse(
        TotalResponses: all.Count,
        Attending:      attending.Count,
        NotAttending:   all.Count - attending.Count,
        TotalGuests:    attending.Sum(e => e.Guests)
    ));
}).RequireRateLimiting("admin");

// DELETE /api/rsvp/{id}  (admin)
app.MapDelete("/api/rsvp/{id:int}", async (HttpContext ctx, int id, AppDbContext db) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();

    var entry = await db.RsvpEntries.FindAsync(id);
    if (entry is null) return Results.NotFound();

    db.RsvpEntries.Remove(entry);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireRateLimiting("admin");

app.Run();

static RsvpResponse ToResponse(RsvpEntry e) => new(
    e.Id, e.FirstName, e.LastName, e.Phone, e.Guests, e.Attending, e.CreatedAt);
