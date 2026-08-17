namespace SyntaxCircus.AspNetCore.Authentication;

public sealed class JwtBearerAuthenticationOptions
{
    public const string SectionName = "Authentication:JwtBearer";

    /// <summary>OIDC authority used to discover signing keys for the primary scheme.</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>Accepted audiences for the primary (OIDC-backed) scheme.</summary>
    public IReadOnlyList<string> Audiences { get; set; } = [];

    /// <summary>
    /// Accepted issuers, in addition to <see cref="Authority"/>, for the primary scheme. Any entry
    /// here that differs from <see cref="Authority"/> also gets its own OIDC discovery
    /// (<c>/.well-known/openid-configuration</c> + JWKS), so tokens issued by genuinely distinct
    /// OIDC applications — e.g. separate Web/Admin/Mobile registrations against the same identity
    /// provider, each with its own signing keys — validate correctly, not just tokens whose issuer
    /// claim happens to differ while sharing <see cref="Authority"/>'s keys. Discovery happens once
    /// per distinct issuer regardless of list size, and is skipped entirely (matching prior
    /// behavior) when every entry here equals <see cref="Authority"/> or the list is empty.
    /// </summary>
    public IReadOnlyList<string> TrustedIssuers { get; set; } = [];

    /// <summary>
    /// Whether the OIDC discovery endpoints (<see cref="Authority"/> and any distinct entries in
    /// <see cref="TrustedIssuers"/>) must be served over HTTPS. Unset (<see langword="null"/>)
    /// leaves <see cref="Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions.RequireHttpsMetadata"/>'s
    /// own default (<see langword="true"/>) untouched.
    /// </summary>
    public bool? RequireHttpsMetadata { get; set; }

    /// <summary>
    /// Whether inbound claim types are remapped from their short/JWT names to the long
    /// <see cref="System.Security.Claims.ClaimTypes"/> equivalents — ASP.NET Core's historical
    /// default. Set to <see langword="false"/> to preserve raw claim types as they appear in the
    /// token (e.g. a custom <c>"roles"</c> claim, instead of it being remapped). Unset
    /// (<see langword="null"/>) leaves
    /// <see cref="Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions.MapInboundClaims"/>'s
    /// own default (<see langword="true"/>) untouched.
    /// </summary>
    public bool? MapInboundClaims { get; set; }

    /// <summary>
    /// Overrides <see cref="Microsoft.IdentityModel.Tokens.TokenValidationParameters.RoleClaimType"/>
    /// for the primary scheme — the claim type consulted by role-based authorization
    /// (<c>ClaimsPrincipal.IsInRole</c>). Unset (<see langword="null"/>) leaves the default
    /// (<see cref="System.Security.Claims.ClaimTypes.Role"/>) untouched.
    /// </summary>
    public string? RoleClaimType { get; set; }

    /// <summary>
    /// Overrides <see cref="Microsoft.IdentityModel.Tokens.TokenValidationParameters.NameClaimType"/>
    /// for the primary scheme — the claim type used for <c>ClaimsPrincipal.Identity.Name</c>. Unset
    /// (<see langword="null"/>) leaves the default
    /// (<see cref="System.Security.Claims.ClaimTypes.Name"/>) untouched.
    /// </summary>
    public string? NameClaimType { get; set; }

    /// <summary>
    /// When <see langword="true"/>, a dev-diagnostics <c>OnAuthenticationFailed</c> handler is added
    /// to the primary scheme that logs the validation exception whenever
    /// <see cref="Microsoft.Extensions.Hosting.IHostEnvironment.IsDevelopment"/> is true (resolved
    /// per-request from <c>HttpContext.RequestServices</c>; a no-op if <c>IHostEnvironment</c> isn't
    /// registered). Has no effect outside Development. Defaults to <see langword="false"/> (opt-in)
    /// so upgrading without touching config produces no behavior change. Chains to (runs before) any
    /// <c>OnAuthenticationFailed</c> handler you've already configured on
    /// <see cref="Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions.Events"/> at the
    /// point <c>AddSyntaxCircusJwtBearer</c> runs; if you replace <c>Events</c> wholesale afterwards
    /// (e.g. via a later <c>PostConfigure</c>), you take over this handler's slot entirely, same as
    /// any other <c>IConfigureOptions</c> composition in ASP.NET Core.
    /// </summary>
    public bool LogAuthenticationFailuresInDevelopment { get; set; }

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
