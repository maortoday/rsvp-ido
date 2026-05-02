namespace RsvpApi.Dtos;

public record SubmitRsvpRequest(
    string FirstName,
    string LastName,
    string Phone,
    int    Guests,
    bool   Attending
);

public record RsvpResponse(
    int      Id,
    string   FirstName,
    string   LastName,
    string   Phone,
    int      Guests,
    bool     Attending,
    DateTime CreatedAt
);

public record StatsResponse(
    int TotalResponses,
    int Attending,
    int NotAttending,
    int TotalGuests
);

public record SettingsPublicDto(
    string PhoneNumber,
    string Location,
    string FamilyText,
    string ConfirmColor,
    bool   HasImage
);

public record SettingsUpdateDto(
    string? PhoneNumber,
    string? Location,
    string? FamilyText,
    string? ConfirmColor
);
