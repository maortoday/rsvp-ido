namespace RsvpApi.Models;

public class SiteSettings
{
    public int     Id             { get; set; }
    public string  PhoneNumber    { get; set; } = "0523010253";
    public string  Location       { get; set; } = "שמחה הולצברג 12 באר שבע";
    public string  FamilyText     { get; set; } = "משפחת אמונה — אלי, מורן, אור ונועם";
    public string  ConfirmColor   { get; set; } = "#3a6b47";
    public byte[]? ImageData      { get; set; }
    public string  ImageMimeType  { get; set; } = "image/jpeg";
}
