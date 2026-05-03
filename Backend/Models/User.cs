namespace RsvpApi.Models;

public class User
{
    public int       Id                   { get; set; }
    public string    Email                { get; set; } = "";
    public string    PasswordHash         { get; set; } = "";
    public string    Slug                 { get; set; } = "";
    public string    PhoneNumber          { get; set; } = "";
    public string    RecoveryCode         { get; set; } = "";
    public string    EmailResetToken      { get; set; } = "";
    public DateTime? EmailResetExpiry     { get; set; }
    public string    SmsResetCode         { get; set; } = "";
    public DateTime? SmsResetExpiry       { get; set; }
    public string    WhatsAppApiKey       { get; set; } = "";
    public DateTime  CreatedAt            { get; set; } = DateTime.UtcNow;
}
