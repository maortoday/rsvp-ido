namespace RsvpApi.Dtos;

public record RegisterRequest(
    string Email,
    string Password,
    string Slug,
    string PhoneNumber,
    string EventTitle,
    string EventDate,
    string? WhatsAppApiKey
);

public record RegisterResponse(string Slug, string RecoveryCode);

public record LoginRequest(string Email, string Password);

public record ResetPasswordRequest(string Email, string RecoveryCode, string NewPassword);

public record ForgotEmailRequest(string Email);
public record ResetEmailRequest(string Email, string Token, string NewPassword);

public record ForgotSmsRequest(string Email);
public record ResetSmsRequest(string Email, string Code, string NewPassword);

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
    string EventTitle,
    string EventDate,
    string ConfirmColor,
    string DeclineColor,
    bool   HasImage
);

public record SettingsUpdateDto(
    string? PhoneNumber,
    string? Location,
    string? FamilyText,
    string? EventTitle,
    string? EventDate,
    string? ConfirmColor,
    string? DeclineColor,
    string? WhatsAppApiKey
);
