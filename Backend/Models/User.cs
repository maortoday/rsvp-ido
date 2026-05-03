namespace RsvpApi.Models;

public class User
{
    public int      Id           { get; set; }
    public string   Email        { get; set; } = "";
    public string   PasswordHash { get; set; } = "";
    public string   Slug         { get; set; } = "";
    public string   RecoveryCode { get; set; } = "";
    public DateTime CreatedAt    { get; set; } = DateTime.UtcNow;
}
