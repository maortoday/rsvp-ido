namespace RsvpApi.Models;

public class RsvpEntry
{
    public int    Id        { get; set; }
    public string FirstName { get; set; } = "";
    public string LastName  { get; set; } = "";
    public string Phone     { get; set; } = "";
    public int    Guests    { get; set; } = 1;
    public bool   Attending { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
