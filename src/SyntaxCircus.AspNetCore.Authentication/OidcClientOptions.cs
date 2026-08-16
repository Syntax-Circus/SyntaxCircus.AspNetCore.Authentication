namespace SyntaxCircus.AspNetCore.Authentication;

/// <summary>Base OIDC client shape shared across cookie/OIDC and JWT-bearer registration paths.</summary>
public record OidcClientOptions
{
    public string Authority { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    public string ClientSecret { get; set; } = string.Empty;

    public string[] Scopes { get; set; } = ["openid", "profile", "email"];
}
