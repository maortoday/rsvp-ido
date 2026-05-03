using System.Security.Cryptography;
using System.Threading.RateLimiting;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using MimeKit;
using RsvpApi.Data;
using RsvpApi.Dtos;
using RsvpApi.Models;

var builder = WebApplication.CreateBuilder(args);

var port = Environment.GetEnvironmentVariable("PORT") ?? "5050";
builder.WebHost.UseUrls($"http://+:{port}");

// ── Config ────────────────────────────────────────────────
var allowedOrigin   = builder.Configuration["AllowedOrigin"]      ?? "*";
var superAdminPw    = builder.Configuration["SuperAdminPassword"]  ?? "";
var smtpHost        = builder.Configuration["SmtpHost"]            ?? "";
var smtpPort        = int.TryParse(builder.Configuration["SmtpPort"], out var sp) ? sp : 587;
var smtpUser        = builder.Configuration["SmtpUser"]            ?? "";
var smtpPass        = builder.Configuration["SmtpPass"]            ?? "";
var smtpFrom        = builder.Configuration["SmtpFrom"]            ?? smtpUser;
var twilioSid       = builder.Configuration["TwilioSid"]           ?? "";
var twilioToken     = builder.Configuration["TwilioToken"]         ?? "";
var twilioFrom      = builder.Configuration["TwilioFrom"]          ?? "";
var appOrigin       = builder.Configuration["AppOrigin"]           ?? "";

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
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = 5, Window = TimeSpan.FromMinutes(10), QueueLimit = 0 }));
    opt.AddPolicy("admin", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = 30, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    opt.AddPolicy("auth", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(10), QueueLimit = 0 }));
});

var app = builder.Build();

// ── DB migration ──────────────────────────────────────────
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();

    db.Database.ExecuteSqlRaw("""
        CREATE TABLE IF NOT EXISTS "Users" (
            "Id"                 INTEGER NOT NULL CONSTRAINT "PK_Users" PRIMARY KEY AUTOINCREMENT,
            "Email"              TEXT    NOT NULL DEFAULT '',
            "PasswordHash"       TEXT    NOT NULL DEFAULT '',
            "Slug"               TEXT    NOT NULL DEFAULT '',
            "PhoneNumber"        TEXT    NOT NULL DEFAULT '',
            "RecoveryCode"       TEXT    NOT NULL DEFAULT '',
            "EmailResetToken"    TEXT    NOT NULL DEFAULT '',
            "EmailResetExpiry"   TEXT,
            "SmsResetCode"       TEXT    NOT NULL DEFAULT '',
            "SmsResetExpiry"     TEXT,
            "CreatedAt"          TEXT    NOT NULL DEFAULT ''
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

    foreach (var sql in new[]
    {
        "ALTER TABLE Users        ADD COLUMN \"PhoneNumber\"      TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE Users        ADD COLUMN \"EmailResetToken\"  TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE Users        ADD COLUMN \"EmailResetExpiry\" TEXT",
        "ALTER TABLE Users        ADD COLUMN \"SmsResetCode\"     TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE Users        ADD COLUMN \"SmsResetExpiry\"   TEXT",
        "ALTER TABLE SiteSettings ADD COLUMN \"Slug\"             TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE SiteSettings ADD COLUMN \"DeclineColor\"     TEXT NOT NULL DEFAULT '#b0b8c4'",
        "ALTER TABLE SiteSettings ADD COLUMN \"EventTitle\"       TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE SiteSettings ADD COLUMN \"EventDate\"        TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE RsvpEntries  ADD COLUMN \"Slug\"             TEXT NOT NULL DEFAULT ''",
    })
    { try { db.Database.ExecuteSqlRaw(sql); } catch { } }
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

var dfo = new DefaultFilesOptions();
dfo.DefaultFileNames.Clear();
dfo.DefaultFileNames.Add("register.html");
app.UseDefaultFiles(dfo);
app.UseStaticFiles();

// ── Helpers ───────────────────────────────────────────────
static string Sanitize(string s) =>
    s.Trim().Replace("<", "").Replace(">", "").Replace("\"", "");

static bool IsValidPhone(string p) =>
    System.Text.RegularExpressions.Regex.IsMatch(p, @"^[\d\-\+\s\(\)]{7,20}$");

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

static string GenerateRecoveryCode() =>
    Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToUpper();

bool IsAdmin(HttpContext ctx, User? user) =>
    user is not null &&
    ctx.Request.Headers.TryGetValue("X-Admin-Password", out var val) &&
    VerifyPassword(val!, user.PasswordHash);

bool IsSuperAdmin(HttpContext ctx) =>
    !string.IsNullOrEmpty(superAdminPw) &&
    ctx.Request.Headers.TryGetValue("X-Super-Admin-Password", out var val) &&
    CryptographicOperations.FixedTimeEquals(
        System.Text.Encoding.UTF8.GetBytes(val.ToString().PadRight(64)),
        System.Text.Encoding.UTF8.GetBytes(superAdminPw.PadRight(64)));

async Task SendEmailAsync(string to, string subject, string htmlBody)
{
    if (string.IsNullOrEmpty(smtpHost)) return;
    try
    {
        var msg = new MimeMessage();
        msg.From.Add(new MailboxAddress("מערכת אישורי הגעה", smtpFrom));
        msg.To.Add(new MailboxAddress("", to));
        msg.Subject = subject;
        msg.Body    = new TextPart("html") { Text = htmlBody };
        using var client = new SmtpClient();
        await client.ConnectAsync(smtpHost, smtpPort, SecureSocketOptions.StartTls);
        await client.AuthenticateAsync(smtpUser, smtpPass);
        await client.SendAsync(msg);
        await client.DisconnectAsync(true);
    }
    catch { }
}

async Task SendSmsAsync(string to, string body)
{
    if (string.IsNullOrEmpty(twilioSid)) return;
    try
    {
        using var http = new HttpClient();
        var creds = Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes($"{twilioSid}:{twilioToken}"));
        http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", creds);
        await http.PostAsync(
            $"https://api.twilio.com/2010-04-01/Accounts/{twilioSid}/Messages.json",
            new FormUrlEncodedContent(new Dictionary<string, string>
                { ["To"] = to, ["From"] = twilioFrom, ["Body"] = body }));
    }
    catch { }
}

static RsvpResponse ToResponse(RsvpEntry e) =>
    new(e.Id, e.FirstName, e.LastName, e.Phone, e.Guests, e.Attending, e.CreatedAt);

// ── Auth ──────────────────────────────────────────────────

app.MapPost("/api/auth/register", async (RegisterRequest req, AppDbContext db, HttpContext ctx) =>
{
    var email = req.Email?.ToLower().Trim() ?? "";
    var slug  = req.Slug?.ToLower().Trim()  ?? "";

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
        PhoneNumber  = req.PhoneNumber?.Trim() ?? "",
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

app.MapPost("/api/auth/login", async (LoginRequest req, AppDbContext db) =>
{
    var email = req.Email?.ToLower().Trim() ?? "";
    var user  = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user is null || !VerifyPassword(req.Password ?? "", user.PasswordHash))
        return Results.Unauthorized();
    return Results.Ok(new { slug = user.Slug });
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/reset", async (ResetPasswordRequest req, AppDbContext db) =>
{
    var email = req.Email?.ToLower().Trim() ?? "";
    var user  = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user is null || !VerifyPassword(req.RecoveryCode ?? "", user.RecoveryCode))
        return Results.BadRequest(new { error = "מייל או קוד שחזור שגויים" });
    if (string.IsNullOrWhiteSpace(req.NewPassword) || req.NewPassword.Length < 6)
        return Results.BadRequest(new { error = "הסיסמה חייבת להיות לפחות 6 תווים" });
    user.PasswordHash = HashPassword(req.NewPassword);
    user.RecoveryCode = HashPassword(GenerateRecoveryCode() + GenerateRecoveryCode());
    await db.SaveChangesAsync();
    return Results.Ok(new { success = true });
}).RequireRateLimiting("auth");

// Email reset
app.MapPost("/api/auth/forgot-email", async (ForgotEmailRequest req, AppDbContext db) =>
{
    var email = req.Email?.ToLower().Trim() ?? "";
    var user  = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user is not null)
    {
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        user.EmailResetToken  = HashPassword(rawToken);
        user.EmailResetExpiry = DateTime.UtcNow.AddHours(1);
        await db.SaveChangesAsync();

        var origin   = string.IsNullOrEmpty(appOrigin) ? "" : appOrigin;
        var resetUrl = $"{origin}/forgot.html?method=email&token={Uri.EscapeDataString(rawToken)}&email={Uri.EscapeDataString(email)}";
        var html = $"""
            <div dir="rtl" style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:32px;background:#fdfaf4;border-radius:16px;border:1px solid #e8c06a">
              <h2 style="color:#1a2a4a;margin-bottom:8px">איפוס סיסמה</h2>
              <p style="color:#555;line-height:1.7">קיבלנו בקשה לאיפוס הסיסמה שלך. לחצו על הכפתור להמשך:</p>
              <div style="text-align:center;margin:28px 0">
                <a href="{resetUrl}" style="background:linear-gradient(135deg,#c9943a,#a07020);color:white;padding:14px 32px;border-radius:10px;text-decoration:none;font-weight:bold;font-size:16px">
                  לאיפוס הסיסמה
                </a>
              </div>
              <p style="color:#aaa;font-size:12px">הקישור תקף לשעה אחת. אם לא ביקשתם איפוס — התעלמו מהודעה זו.</p>
            </div>
        """;
        _ = Task.Run(() => SendEmailAsync(email, "איפוס סיסמה — מערכת אישורי הגעה", html));
    }
    return Results.Ok(new { message = "אם המייל קיים במערכת, נשלחה הוראת איפוס" });
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/reset-email", async (ResetEmailRequest req, AppDbContext db) =>
{
    var email = req.Email?.ToLower().Trim() ?? "";
    var user  = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user is null || user.EmailResetExpiry < DateTime.UtcNow || string.IsNullOrEmpty(user.EmailResetToken))
        return Results.BadRequest(new { error = "קישור האיפוס לא תקין או פג תוקף" });
    if (!VerifyPassword(req.Token ?? "", user.EmailResetToken))
        return Results.BadRequest(new { error = "קישור האיפוס לא תקין" });
    if (string.IsNullOrWhiteSpace(req.NewPassword) || req.NewPassword.Length < 6)
        return Results.BadRequest(new { error = "הסיסמה חייבת להיות לפחות 6 תווים" });
    user.PasswordHash    = HashPassword(req.NewPassword);
    user.EmailResetToken = "";
    user.EmailResetExpiry = null;
    await db.SaveChangesAsync();
    return Results.Ok(new { success = true });
}).RequireRateLimiting("auth");

// SMS reset
app.MapPost("/api/auth/forgot-sms", async (ForgotSmsRequest req, AppDbContext db) =>
{
    var email = req.Email?.ToLower().Trim() ?? "";
    var user  = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user is not null && !string.IsNullOrEmpty(user.PhoneNumber))
    {
        var code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
        user.SmsResetCode   = HashPassword(code);
        user.SmsResetExpiry = DateTime.UtcNow.AddMinutes(10);
        await db.SaveChangesAsync();
        _ = Task.Run(() => SendSmsAsync(user.PhoneNumber, $"קוד לאיפוס סיסמה: {code}\nתקף ל-10 דקות."));
    }
    return Results.Ok(new { message = "אם המייל קיים ומשויך למספר טלפון, נשלח SMS" });
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/reset-sms", async (ResetSmsRequest req, AppDbContext db) =>
{
    var email = req.Email?.ToLower().Trim() ?? "";
    var user  = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user is null || user.SmsResetExpiry < DateTime.UtcNow || string.IsNullOrEmpty(user.SmsResetCode))
        return Results.BadRequest(new { error = "הקוד לא תקין או פג תוקף" });
    if (!VerifyPassword(req.Code ?? "", user.SmsResetCode))
        return Results.BadRequest(new { error = "הקוד שגוי" });
    if (string.IsNullOrWhiteSpace(req.NewPassword) || req.NewPassword.Length < 6)
        return Results.BadRequest(new { error = "הסיסמה חייבת להיות לפחות 6 תווים" });
    user.PasswordHash  = HashPassword(req.NewPassword);
    user.SmsResetCode  = "";
    user.SmsResetExpiry = null;
    await db.SaveChangesAsync();
    return Results.Ok(new { success = true });
}).RequireRateLimiting("auth");

// ── Super admin ───────────────────────────────────────────

app.MapGet("/api/superadmin/users", async (HttpContext ctx, AppDbContext db) =>
{
    if (!IsSuperAdmin(ctx)) return Results.Unauthorized();
    var users    = await db.Users.OrderByDescending(u => u.CreatedAt).ToListAsync();
    var settings = await db.SiteSettings.ToListAsync();
    var rsvps    = await db.RsvpEntries.ToListAsync();

    var result = users.Select(u =>
    {
        var s    = settings.FirstOrDefault(x => x.Slug == u.Slug);
        var r    = rsvps.Where(x => x.Slug == u.Slug).ToList();
        var att  = r.Where(x => x.Attending).ToList();
        return new
        {
            id          = u.Id,
            email       = u.Email,
            slug        = u.Slug,
            phone       = u.PhoneNumber,
            createdAt   = u.CreatedAt,
            eventTitle  = s?.EventTitle ?? "",
            eventDate   = s?.EventDate  ?? "",
            totalRsvps  = r.Count,
            attending   = att.Count,
            totalGuests = att.Sum(x => x.Guests)
        };
    });
    return Results.Ok(result);
}).RequireRateLimiting("admin");

app.MapGet("/api/superadmin/stats", async (HttpContext ctx, AppDbContext db) =>
{
    if (!IsSuperAdmin(ctx)) return Results.Unauthorized();
    return Results.Ok(new
    {
        totalUsers  = await db.Users.CountAsync(),
        totalEvents = await db.SiteSettings.CountAsync(),
        totalRsvps  = await db.RsvpEntries.CountAsync(),
        attending   = await db.RsvpEntries.CountAsync(e => e.Attending)
    });
}).RequireRateLimiting("admin");

app.MapDelete("/api/superadmin/reset-db", async (HttpContext ctx, AppDbContext db) =>
{
    if (!IsSuperAdmin(ctx)) return Results.Unauthorized();
    await db.Database.ExecuteSqlRawAsync("DELETE FROM RsvpEntries");
    await db.Database.ExecuteSqlRawAsync("DELETE FROM Users");
    await db.Database.ExecuteSqlRawAsync("DELETE FROM SiteSettings");
    await db.Database.ExecuteSqlRawAsync("DELETE FROM sqlite_sequence WHERE name IN ('RsvpEntries','Users','SiteSettings')");
    return Results.Ok(new { message = "בסיס הנתונים אופס בהצלחה" });
}).RequireRateLimiting("admin");

// ── RSVP endpoints ────────────────────────────────────────

app.MapPost("/api/{slug}/rsvp", async (string slug, SubmitRsvpRequest req, AppDbContext db) =>
{
    var eventUser = await db.Users.FirstOrDefaultAsync(u => u.Slug == slug);
    if (eventUser is null) return Results.NotFound(new { error = "האירוע לא נמצא" });

    if (string.IsNullOrWhiteSpace(req.FirstName) || string.IsNullOrWhiteSpace(req.LastName) || string.IsNullOrWhiteSpace(req.Phone))
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

    // SMS notification to event admin
    if (!string.IsNullOrEmpty(eventUser.PhoneNumber))
    {
        var status    = req.Attending ? $"מגיע/ה ✓ ({req.Guests} אורחים)" : "לא מגיע/ה ✗";
        var notifBody = $"אישור הגעה חדש!\n{entry.FirstName} {entry.LastName} — {status}\nטלפון: {entry.Phone}";
        _ = Task.Run(() => SendSmsAsync(eventUser.PhoneNumber, notifBody));
    }

    return Results.Created($"/api/{slug}/rsvp/{entry.Id}", ToResponse(entry));
}).RequireRateLimiting("rsvp-submit");

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

app.MapGet("/api/{slug}/rsvp/stats", async (string slug, HttpContext ctx, AppDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Slug == slug);
    if (!IsAdmin(ctx, user)) return Results.Unauthorized();
    var all      = await db.RsvpEntries.Where(e => e.Slug == slug).ToListAsync();
    var attending = all.Where(e => e.Attending).ToList();
    return Results.Ok(new StatsResponse(all.Count, attending.Count, all.Count - attending.Count, attending.Sum(e => e.Guests)));
}).RequireRateLimiting("admin");

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

// ── Settings endpoints ────────────────────────────────────

app.MapGet("/api/{slug}/settings", async (string slug, AppDbContext db) =>
{
    var s = await db.SiteSettings.FirstOrDefaultAsync(x => x.Slug == slug);
    if (s is null) return Results.NotFound();
    return Results.Ok(new SettingsPublicDto(
        s.PhoneNumber, s.Location, s.FamilyText, s.EventTitle, s.EventDate,
        s.ConfirmColor, s.DeclineColor, s.ImageData != null));
});

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

app.MapPost("/api/{slug}/settings/image", async (string slug, HttpContext ctx, AppDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Slug == slug);
    if (!IsAdmin(ctx, user)) return Results.Unauthorized();
    var form = await ctx.Request.ReadFormAsync();
    var file = form.Files.GetFile("image");
    if (file is null || file.Length == 0) return Results.BadRequest(new { error = "לא נבחר קובץ" });
    if (!new[] { "image/jpeg", "image/png", "image/webp" }.Contains(file.ContentType.ToLower()))
        return Results.BadRequest(new { error = "סוג קובץ לא נתמך (JPG/PNG/WebP)" });
    if (file.Length > 8 * 1024 * 1024) return Results.BadRequest(new { error = "הקובץ גדול מדי (מקסימום 8MB)" });
    using var ms = new MemoryStream();
    await file.CopyToAsync(ms);
    var s = await db.SiteSettings.FirstOrDefaultAsync(x => x.Slug == slug);
    if (s is null) { s = new SiteSettings { Slug = slug }; db.SiteSettings.Add(s); }
    s.ImageData     = ms.ToArray();
    s.ImageMimeType = file.ContentType;
    await db.SaveChangesAsync();
    return Results.Ok(new { success = true });
}).RequireRateLimiting("admin");

app.MapGet("/api/{slug}/settings/image", async (string slug, AppDbContext db) =>
{
    var s = await db.SiteSettings.FirstOrDefaultAsync(x => x.Slug == slug);
    if (s?.ImageData is null) return Results.NotFound();
    return Results.File(s.ImageData, s.ImageMimeType);
});

app.Run();
