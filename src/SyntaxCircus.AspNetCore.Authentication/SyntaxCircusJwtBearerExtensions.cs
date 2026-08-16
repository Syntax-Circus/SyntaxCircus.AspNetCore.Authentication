using System.Text;

namespace SyntaxCircus.AspNetCore.Authentication;

public static class SyntaxCircusJwtBearerExtensions
{
    public const string DeviceScheme = "SyntaxCircusDevice";
    public const string PolicyScheme = "SyntaxCircusJwt";

    /// <summary>
    /// Registers JWT bearer authentication: a primary scheme validating OIDC-discovered signing
    /// keys against <see cref="JwtBearerAuthenticationOptions.Authority"/>, and — when
    /// <see cref="JwtBearerAuthenticationOptions.DeviceToken"/> is enabled — a second symmetric-key
    /// scheme for self-issued device/M2M tokens, dispatched to automatically by sniffing the
    /// incoming JWT's <c>alg</c> header (see <see cref="JwtSchemeSelector"/>).
    /// </summary>
    public static AuthenticationBuilder AddSyntaxCircusJwtBearer(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = JwtBearerAuthenticationOptions.SectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var options = new JwtBearerAuthenticationOptions();
        configuration.GetSection(sectionName).Bind(options);

        var defaultScheme = options.DeviceToken.Enabled ? PolicyScheme : JwtBearerDefaults.AuthenticationScheme;
        var authenticationBuilder = services.AddAuthentication(defaultScheme);

        authenticationBuilder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, bearerOptions =>
        {
            bearerOptions.Authority = options.Authority;

            if (options.Audiences.Count > 0)
            {
                bearerOptions.TokenValidationParameters.ValidAudiences = options.Audiences;
            }

            if (options.TrustedIssuers.Count > 0)
            {
                bearerOptions.TokenValidationParameters.ValidIssuers = options.TrustedIssuers;
            }
        });

        if (options.DeviceToken.Enabled)
        {
            authenticationBuilder.AddJwtBearer(DeviceScheme, deviceOptions =>
            {
                deviceOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = options.DeviceToken.Issuer,
                    ValidateAudience = true,
                    ValidAudience = options.DeviceToken.Audience,
                    ValidateLifetime = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.DeviceToken.SigningKey)),
                };
            });

            authenticationBuilder.AddPolicyScheme(PolicyScheme, PolicyScheme, policyOptions =>
            {
                policyOptions.ForwardDefaultSelector = context => JwtSchemeSelector.SelectScheme(context, options);
            });
        }

        return authenticationBuilder;
    }
}
