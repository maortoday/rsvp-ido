namespace RsvpApi.Models;

public class SiteSettings
{
    public int     Id            { get; set; }
    public string  Slug          { get; set; } = "";
    public string  PhoneNumber   { get; set; } = "";
    public string  Location      { get; set; } = "";
    public string  FamilyText    { get; set; } = "";
    public string  EventTitle    { get; set; } = "";
    public string  EventDate     { get; set; } = "";
    public string  ConfirmColor  { get; set; } = "#3a6b47";
    public string  DeclineColor  { get; set; } = "#b0b8c4";
    public string  WhatsAppTemplate { get; set; } = "";
    public byte[]? ImageData        { get; set; }
    public string  ImageMimeType    { get; set; } = "image/jpeg";
}
