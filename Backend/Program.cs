using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using RsvpApi.Data;
using RsvpApi.Dtos;
using RsvpApi.Models;

var builder = WebApplication.CreateBuilder(args);

var port = Environment.GetEnvironmentVariable("PORT") ?? "5050";
builder.WebHost.UseUrls($"http://+:{port}");

var allowedOrigin = builder.Configuration["AllowedOrigin"] ?? "*";

builder.Services.AddDbContext<AppDbContext>(opt =>
    opt.UseSqlite("Data Source=rsvp.db"));

builder.Services.AddCors(opt =>
    opt.AddDefaultPolicy(p =>
    {
        if (allowedOrigin == "*")
            p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
        else
            p.WithOrigins(allowedOrigin).AllowAnyHeader().AllowAnyMethod();
    }));

builder.Services.AddRateLimiter(opt =>
{
    opt.RejectionStatusCode = 429;

    opt.AddPolicy("rsvp-submit", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
                { PermitLimit = 5, Window = TimeSpan.FromMinutes(10), QueueLimit = 0 }));

    opt.AddPolicy("admin", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
                { PermitLimit = 30, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));

    opt.AddPolicy("auth", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
                { PermitLimit = 10, Window = TimeSpan.FromMinutes(10), QueueLimit = 0 }));
});

var app = builder.Build();

// ── DB migration on startup ───────────────────────────────
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();

    db.Database.ExecuteSqlRaw("""
        CREATE TABLE IF NOT EXISTS "Users" (
            "Id"           INTEGER NOT NULL CONSTRAINT "PK_Users" PRIMARY KEY AUTOINCREMENT,
            "Email"        TEXT    NOT NULL DEFAULT '',
            "PasswordHash" TEXT    NOT NULL DEFAULT '',
            "Slug"         TEXT    NOT NULL DEFAULT '',
            "RecoveryCode" TEXT    NOT NULL DEFAULT '',
            "CreatedAt"    TEXT    NOT NULL DEFAULT ''
        )
    """);

    db.Database.ExecuteSqlRaw("""
        CREATE TABLE IF NOT EXISTS "SiteSettings" (
            "Id"            INTEGER NOT NULL CONSTRAINT "PK_SiteSettings" PRIMARY KEY AUTOINCREMENT,
            "Slug"          TEXT    NOT NULL DEFAULT '',
            "PhoneNumber"   TEXT    NOT NULL DEFAULT '',
            "Location"      TEXT    NOT NULL DEFAULT '',
            "FamilyText"    TEXT    NOT NULL DEFAULT '',
            "EventTitle"    TEXT    NOT NULL DEFAULT '',
            "EventDate"     TEXT    NOT NULL DEFAULT '',
            "ConfirmColor"  TEXT    NOT NULL DEFAULT '#3a6b47',
            "DeclineColor"  TEXT    NOT NULL DEFAULT '#b0b8c4',
            "ImageData"     BLOB,
            "ImageMimeType" TEXT    NOT NULL DEFAULT 'image/jpeg'
        )
    """);

    // Add columns to pre-existing tables (safe to run on every start)
    foreach (var sql in new[]
    {
        "ALTER TABLE SiteSettings ADD COLUMN \"Slug\"         TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE SiteSettings ADD COLUMN \"DeclineColor\" TEXT NOT NULL DEFAULT '#b0b8c4'",
        "ALTER TABLE SiteSettings ADD COLUMN \"EventTitle\"   TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE SiteSettings ADD COLUMN \"EventDate\"    TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE RsvpEntries  ADD COLUMN \"Slug\"         TEXT NOT NULL DEFAULT ''",
    })
    {
        try { db.Database.ExecuteSqlRaw(sql); } catch { /* column already exists */ }
    }
}

// ── Security headers ──────────────────────────────────────
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"]         = "DENY";
    ctx.Response.Headers["Referrer-Policy"]         = "strict-origin-when-cross-origin";
    ctx.Response.Headers["Permissions-Policy"]      = "geolocation=(), camera=(), microphone=()";
    ctx.Response.Headers["Content-Security-Policy"] =
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
    await ctx.Response.WriteAsync($"Error: {ex?.Message}");
}));

app.UseCors();
app.UseRateLimiter();

app.MapGet("/health", () => "ok");

app.UseDefaultFiles();
app.UseStaticFiles();

// ── Helpers ───────────────────────────────────────────────
static string Sanitize(string s) =>
    s.Trim().Replace("<", "").Replace(">", "").Replace("\"", "");

static bool IsValidPhone(string p) =>
    System.Text.RegularExpressions.Regex.IsMatch(p, @"^[\d\-\+\s]{7,15}$");

static bool IsValidSlug(string s) =>
    !string.IsNullOrWhiteSpace(s) &&
    System.Text.RegularExpressions.Regex.IsMatch(s, @"^[a-z0-9\-]{2,30}$");

static string HashPassword(string password)
{
    byte[] salt = RandomNumberGenerator.GetBytes(16);
    var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
    return Convert.ToBase64String(salt) + "." + Convert.ToBase64String(hash);
}

static bool VerifyPassword(string password, string stored)
{
    var parts = stored.Split('.');
    if (parts.Length != 2) return false;
    try
    {
        var salt     = Convert.FromBase64String(parts[0]);
        var expected = Convert.FromBase64String(parts[1]);
        var actual   = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
    catch { return false; }
}

static string GenerateRecoveryCode()
{
    var bytes = RandomNumberGenerator.GetBytes(6);
    return Convert.ToHexString(bytes).ToUpper(); // 12-char hex
}

bool IsAdmin(HttpContext ctx, User? user)
{
    if (user is null) return false;
    if (!ctx.Request.Headers.TryGetValue("X-Admin-Password", out var val)) return false;
    return VerifyPassword(val!, user.PasswordHash);
}

static RsvpResponse ToResponse(RsvpEntry e) =>
    new(e.Id, e.FirstName, e.LastName, e.Phone, e.Guests, e.Attending, e.CreatedAt);

// ── Auth endpoints ─────────────────────────────────────────

// POST /api/auth/register
app.MapPost("/api/auth/register", async (RegisterRequest req, AppDbContext db) =>
{
    var email = req.Email?.ToLower().Trim() ?? "";
    var slug  = req.Slug?.ToLower().Trim() ?? "";

    if (!email.Contains('@') || email.Length < 5)
        return Results.BadRequest(new { error = "כתובת מייל לא תקינה" });
    if (string.IsNullOrWhiteSpace(req.Password) || req.Password.Length < 6)
        return Results.BadRequest(new { error = "הסיסמה חייבת להיות לפחות 6 תווים" });
    if (!IsValidSlug(slug))
        return Results.BadRequest(new { error = "קוד האירוע חייב להכיל אותיות אנגלית קטנות, מספרים או מקף (2-30 תווים)" });

    if (await db.Users.AnyAsync(u => u.Email == email))
        return Results.BadRequest(new { error = "כתובת המייל כבר רשומה במערכת" });
    if (await db.Users.AnyAsync(u => u.Slug == slug))
        return Results.BadRequest(new { error = "קוד האירוע כבר תפוס, נסו קוד אחר" });

    var recoveryCode = GenerateRecoveryCode();
    var user = new User
    {
        Email        = email,
        PasswordHash = HashPassword(req.Password),
        Slug         = slug,
        RecoveryCode = HashPassword(recoveryCode),
        CreatedAt    = DateTime.UtcNow
    };
    db.Users.Add(user);

    db.SiteSettings.Add(new SiteSettings
    {
        Slug       = slug,
        EventTitle = req.EventTitle?.Trim() ?? "",
        EventDate  = req.EventDate?.Trim()  ?? ""
    });

    await db.SaveChangesAsync();
    return Results.Ok(new RegisterResponse(slug, recoveryCode));
}).RequireRateLimiting("auth");

// POST /api/auth/login
app.MapPost("/api/auth/login", async (LoginRequest req, AppDbContext db) =>
{
    var email = req.Email?.ToLower().Trim() ?? "";
    var user  = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user is null || !VerifyPassword(req.Password ?? "", user.PasswordHash))
        return Results.Unauthorized();
    return Results.Ok(new { slug = user.Slug });
}).RequireRateLimiting("auth");

// POST /api/auth/reset
app.MapPost("/api/auth/reset", async (ResetPasswordRequest req, AppDbContext db) =>
{
    var email = req.Email?.ToLower().Trim() ?? "";
    var user  = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user is null)
        return Results.BadRequest(new { error = "כתובת המייל לא נמצאה" });
    if (!VerifyPassword(req.RecoveryCode ?? "", user.RecoveryCode))
        return Results.BadRequest(new { error = "קוד השחזור שגוי" });
    if (string.IsNullOrWhiteSpace(req.NewPassword) || req.NewPassword.Length < 6)
        return Results.BadRequest(new { error = "הסיסמה חייבת להיות לפחות 6 תווים" });

    user.PasswordHash = HashPassword(req.NewPassword);
    // Invalidate old recovery code — user must contact support for a new one
    user.RecoveryCode = HashPassword(GenerateRecoveryCode() + GenerateRecoveryCode());
    await db.SaveChangesAsync();
    return Results.Ok(new { success = true });
}).RequireRateLimiting("auth");

// ── RSVP endpoints (slug-scoped) ──────────────────────────

// POST /api/{slug}/rsvp
app.MapPost("/api/{slug}/rsvp", async (string slug, SubmitRsvpRequest req, AppDbContext db) =>
{
    if (!await db.Users.AnyAsync(u => u.Slug == slug))
        return Results.NotFound(new { error = "האירוע לא נמצא" });

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
        Slug      = slug,
        FirstName = Sanitize(req.FirstName),
        LastName  = Sanitize(req.LastName),
        Phone     = Sanitize(req.Phone),
        Guests    = req.Attending ? req.Guests : 0,
        Attending = req.Attending,
        CreatedAt = DateTime.UtcNow
    };
    db.RsvpEntries.Add(entry);
    await db.SaveChangesAsync();
    return Results.Created($"/api/{slug}/rsvp/{entry.Id}", ToResponse(entry));
}).RequireRateLimiting("rsvp-submit");

// GET /api/{slug}/rsvp (admin)
app.MapGet("/api/{slug}/rsvp", async (string slug, HttpContext ctx, AppDbContext db, string? q) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Slug == slug);
    if (!IsAdmin(ctx, user)) return Results.Unauthorized();

    var query = db.RsvpEntries.Where(e => e.Slug == slug);
    if (!string.IsNullOrWhiteSpace(q))
    {
        var term = q.Trim().ToLower();
        query = query.Where(e =>
            e.FirstName.ToLower().Contains(term) ||
            e.LastName.ToLower().Contains(term)  ||
            e.Phone.Contains(term));
    }
    var list = (await query.OrderByDescending(e => e.CreatedAt).ToListAsync()).Select(ToResponse);
    return Results.Ok(list);
}).RequireRateLimiting("admin");

// GET /api/{slug}/rsvp/stats (admin)
app.MapGet("/api/{slug}/rsvp/stats", async (string slug, HttpContext ctx, AppDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Slug == slug);
    if (!IsAdmin(ctx, user)) return Results.Unauthorized();

    var all      = await db.RsvpEntries.Where(e => e.Slug == slug).ToListAsync();
    var attending = all.Where(e => e.Attending).ToList();
    return Results.Ok(new StatsResponse(
        all.Count, attending.Count,
        all.Count - attending.Count,
        attending.Sum(e => e.Guests)));
}).RequireRateLimiting("admin");

// DELETE /api/{slug}/rsvp/{id} (admin)
app.MapDelete("/api/{slug}/rsvp/{id:int}", async (string slug, int id, HttpContext ctx, AppDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Slug == slug);
    if (!IsAdmin(ctx, user)) return Results.Unauthorized();

    var entry = await db.RsvpEntries.FirstOrDefaultAsync(e => e.Id == id && e.Slug == slug);
    if (entry is null) return Results.NotFound();
    db.RsvpEntries.Remove(entry);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireRateLimiting("admin");

// GET /api/{slug}/settings (public)
app.MapGet("/api/{slug}/settings", async (string slug, AppDbContext db) =>
{
    var s = await db.SiteSettings.FirstOrDefaultAsync(x => x.Slug == slug);
    if (s is null) return Results.NotFound();
    return Results.Ok(new SettingsPublicDto(
        s.PhoneNumber, s.Location, s.FamilyText,
        s.EventTitle, s.EventDate,
        s.ConfirmColor, s.DeclineColor,
        s.ImageData != null));
});

// PUT /api/{slug}/settings (admin)
app.MapPut("/api/{slug}/settings", async (string slug, HttpContext ctx, SettingsUpdateDto req, AppDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Slug == slug);
    if (!IsAdmin(ctx, user)) return Results.Unauthorized();

    var s = await db.SiteSettings.FirstOrDefaultAsync(x => x.Slug == slug);
    if (s is null) { s = new SiteSettings { Slug = slug }; db.SiteSettings.Add(s); }
    if (req.PhoneNumber  is not null) s.PhoneNumber  = Sanitize(req.PhoneNumber);
    if (req.Location     is not null) s.Location     = req.Location.Trim();
    if (req.FamilyText   is not null) s.FamilyText   = req.FamilyText.Trim();
    if (req.EventTitle   is not null) s.EventTitle   = req.EventTitle.Trim();
    if (req.EventDate    is not null) s.EventDate    = req.EventDate.Trim();
    if (req.ConfirmColor is not null) s.ConfirmColor = req.ConfirmColor;
    if (req.DeclineColor is not null) s.DeclineColor = req.DeclineColor;
    await db.SaveChangesAsync();
    return Results.Ok();
}).RequireRateLimiting("admin");

// POST /api/{slug}/settings/image (admin)
app.MapPost("/api/{slug}/settings/image", async (string slug, HttpContext ctx, AppDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Slug == slug);
    if (!IsAdmin(ctx, user)) return Results.Unauthorized();

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
    var s = await db.SiteSettings.FirstOrDefaultAsync(x => x.Slug == slug);
    if (s is null) { s = new SiteSettings { Slug = slug }; db.SiteSettings.Add(s); }
    s.ImageData     = ms.ToArray();
    s.ImageMimeType = file.ContentType;
    await db.SaveChangesAsync();
    return Results.Ok(new { success = true });
}).RequireRateLimiting("admin");

// GET /api/{slug}/settings/image (public)
app.MapGet("/api/{slug}/settings/image", async (string slug, AppDbContext db) =>
{
    var s = await db.SiteSettings.FirstOrDefaultAsync(x => x.Slug == slug);
    if (s?.ImageData is null) return Results.NotFound();
    return Results.File(s.ImageData, s.ImageMimeType);
});

app.Run();
