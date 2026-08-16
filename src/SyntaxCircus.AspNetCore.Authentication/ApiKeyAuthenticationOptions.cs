namespace SyntaxCircus.AspNetCore.Authentication;

public sealed class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string SectionName = "Authentication:ApiKey";

    public string HeaderName { get; set; } = "X-Api-Key";

    /// <summary>Used by <see cref="ConstantApiKeyValidator"/> when no custom <see cref="IApiKeyValidator"/> is registered.</summary>
    public string StaticKey { get; set; } = string.Empty;
}
