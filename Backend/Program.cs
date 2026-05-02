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

// ── Create DB and seed defaults on startup ────────────────
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
    if (!db.SiteSettings.Any())
    {
        db.SiteSettings.Add(new RsvpApi.Models.SiteSettings());
        db.SaveChanges();
    }
}

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
        "frame-src https://maps.google.com https://www.google.com; " +
        "img-src 'self' data: https:;";
    await next();
});

app.UseExceptionHandler(err => err.Run(async ctx =>
{
    var ex = ctx.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;
    ctx.Response.StatusCode = 500;
    await ctx.Response.WriteAsync($"Error: {ex?.Message}\n{ex?.StackTrace}");
}));

app.UseCors();
app.UseRateLimiter();

app.MapGet("/health", () => "ok");

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

// GET /api/settings  (public)
app.MapGet("/api/settings", async (AppDbContext db) =>
{
    var s = await db.SiteSettings.FirstOrDefaultAsync() ?? new RsvpApi.Models.SiteSettings();
    return Results.Ok(new SettingsPublicDto(
        s.PhoneNumber, s.Location, s.FamilyText, s.ConfirmColor, s.ImageData != null));
});

// PUT /api/settings  (admin)
app.MapPut("/api/settings", async (HttpContext ctx, SettingsUpdateDto req, AppDbContext db) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();
    var s = await db.SiteSettings.FirstOrDefaultAsync();
    if (s is null) { s = new RsvpApi.Models.SiteSettings(); db.SiteSettings.Add(s); }
    if (req.PhoneNumber  is not null) s.PhoneNumber  = Sanitize(req.PhoneNumber);
    if (req.Location     is not null) s.Location     = req.Location.Trim();
    if (req.FamilyText   is not null) s.FamilyText   = req.FamilyText.Trim();
    if (req.ConfirmColor is not null) s.ConfirmColor = req.ConfirmColor;
    await db.SaveChangesAsync();
    return Results.Ok();
}).RequireRateLimiting("admin");

// POST /api/settings/image  (admin)
app.MapPost("/api/settings/image", async (HttpContext ctx, AppDbContext db) =>
{
    if (!IsAdmin(ctx)) return Results.Unauthorized();
    var form = await ctx.Request.ReadFormAsync();
    var file = form.Files.GetFile("image");
    if (file is null || file.Length == 0)
        return Results.BadRequest(new { error = "לא נבחר קובץ" });
    var allowed = new[] { "image/jpeg", "image/png", "image/webp" };
    if (!allowed.Contains(file.ContentType.ToLower()))
        return Results.BadRequest(new { error = "סוג קובץ לא נתמך (JPG/PNG/WebP)" });
    if (file.Length > 8 * 1024 * 1024)
        return Results.BadRequest(new { error = "הקובץ גדול מדי (מקסימום 8MB)" });
    using var ms = new MemoryStream();
    await file.CopyToAsync(ms);
    var s = await db.SiteSettings.FirstOrDefaultAsync();
    if (s is null) { s = new RsvpApi.Models.SiteSettings(); db.SiteSettings.Add(s); }
    s.ImageData     = ms.ToArray();
    s.ImageMimeType = file.ContentType;
    await db.SaveChangesAsync();
    return Results.Ok(new { success = true });
}).RequireRateLimiting("admin");

// GET /api/settings/image  (public)
app.MapGet("/api/settings/image", async (AppDbContext db) =>
{
    var s = await db.SiteSettings.FirstOrDefaultAsync();
    if (s?.ImageData is null) return Results.NotFound();
    return Results.File(s.ImageData, s.ImageMimeType);
});

app.Run();

static RsvpResponse ToResponse(RsvpEntry e) => new(
    e.Id, e.FirstName, e.LastName, e.Phone, e.Guests, e.Attending, e.CreatedAt);
