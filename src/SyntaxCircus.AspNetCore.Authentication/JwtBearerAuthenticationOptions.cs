namespace SyntaxCircus.AspNetCore.Authentication;

public sealed class JwtBearerAuthenticationOptions
{
    public const string SectionName = "Authentication:JwtBearer";

    /// <summary>OIDC authority used to discover signing keys for the primary scheme.</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>Accepted audiences for the primary (OIDC-backed) scheme.</summary>
    public IReadOnlyList<string> Audiences { get; set; } = [];

    /// <summary>Accepted issuers, in addition to <see cref="Authority"/>, for the primary scheme.</summary>
    public IReadOnlyList<string> TrustedIssuers { get; set; } = [];

    /// <summary>Optional self-issued symmetric-key "device"/M2M JWT scheme, dispatched to alongside the primary OIDC scheme.</summary>
    public DeviceTokenOptions DeviceToken { get; set; } = new();

    public sealed class DeviceTokenOptions
    {
        public bool Enabled { get; set; }

        public string SigningKey { get; set; } = string.Empty;

        public string Issuer { get; set; } = string.Empty;

        public string Audience { get; set; } = string.Empty;
    }
}
