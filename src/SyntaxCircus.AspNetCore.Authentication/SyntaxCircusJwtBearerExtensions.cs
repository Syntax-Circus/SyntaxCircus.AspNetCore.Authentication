using System.Text;

namespace SyntaxCircus.AspNetCore.Authentication;

public static class SyntaxCircusJwtBearerExtensions
{
    public const string DeviceScheme = "SyntaxCircusDevice";
    public const string PolicyScheme = "SyntaxCircusJwt";

    /// <summary>
    /// Registers JWT bearer authentication: a primary scheme validating OIDC-discovered signing
    /// keys against <see cref="JwtBearerAuthenticationOptions.Authority"/> and, when
    /// <see cref="JwtBearerAuthenticationOptions.TrustedIssuers"/> contains issuer URLs that are
    /// genuinely distinct OIDC applications, against each of those too — and, when
    /// <see cref="JwtBearerAuthenticationOptions.DeviceToken"/> is enabled, a second symmetric-key
    /// scheme for self-issued device/M2M tokens, dispatched to automatically by sniffing the
    /// incoming JWT's <c>alg</c> header (see <see cref="JwtSchemeSelector"/>).
    /// </summary>
    public static AuthenticationBuilder AddSyntaxCircusJwtBearer(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = JwtBearerAuthenticationOptions.SectionName)
        => AddSyntaxCircusJwtBearer(services, configuration, sectionName, configurationManagerFactory: null);

    /// <summary>
    /// Test-only seam: identical to the public overload, but allows substituting how per-issuer
    /// <see cref="IConfigurationManager{T}"/> instances for <see cref="OpenIdConnectConfiguration"/>
    /// are constructed (e.g. pointing at a stub HTTP handler instead of real OIDC discovery
    /// endpoints).
    /// </summary>
    internal static AuthenticationBuilder AddSyntaxCircusJwtBearer(
        IServiceCollection services,
        IConfiguration configuration,
        string sectionName,
        Func<string, IConfigurationManager<OpenIdConnectConfiguration>>? configurationManagerFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var options = new JwtBearerAuthenticationOptions();
        configuration.GetSection(sectionName).Bind(options);

        var defaultScheme = options.DeviceToken.Enabled ? PolicyScheme : JwtBearerDefaults.AuthenticationScheme;
        var authenticationBuilder = services.AddAuthentication(defaultScheme);

        var additionalIssuers = options.TrustedIssuers
            .Where(issuer => !string.IsNullOrWhiteSpace(issuer) && !string.Equals(issuer, options.Authority, StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        authenticationBuilder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, bearerOptions =>
        {
            bearerOptions.Authority = options.Authority;

            if (options.RequireHttpsMetadata.HasValue)
            {
                bearerOptions.RequireHttpsMetadata = options.RequireHttpsMetadata.Value;
            }

            if (options.MapInboundClaims.HasValue)
            {
                bearerOptions.MapInboundClaims = options.MapInboundClaims.Value;
            }

            if (options.Audiences.Count > 0)
            {
                bearerOptions.TokenValidationParameters.ValidAudiences = options.Audiences;
            }

            if (options.TrustedIssuers.Count > 0)
            {
                bearerOptions.TokenValidationParameters.ValidIssuers = options.TrustedIssuers;
            }

            if (options.RoleClaimType is not null)
            {
                bearerOptions.TokenValidationParameters.RoleClaimType = options.RoleClaimType;
            }

            if (options.NameClaimType is not null)
            {
                bearerOptions.TokenValidationParameters.NameClaimType = options.NameClaimType;
            }

            if (additionalIssuers.Length > 0 && !string.IsNullOrWhiteSpace(options.Authority))
            {
                ConfigureMultiIssuerKeyDiscovery(bearerOptions, options, additionalIssuers, configurationManagerFactory);
            }

            if (options.LogAuthenticationFailuresInDevelopment)
            {
                ConfigureAuthenticationFailedDiagnostics(bearerOptions);
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

    /// <summary>
    /// Fans out OIDC discovery across <see cref="JwtBearerAuthenticationOptions.Authority"/> and
    /// every issuer in <paramref name="additionalIssuers"/>, merging the resulting signing keys via
    /// <see cref="TokenValidationParameters.IssuerSigningKeyResolver"/>. Only called when
    /// <paramref name="additionalIssuers"/> is non-empty, so the common single-issuer case never
    /// pays for this — ASP.NET Core builds its own single <see cref="ConfigurationManager{T}"/> from
    /// <see cref="JwtBearerOptions.Authority"/> exactly as before.
    /// </summary>
    private static void ConfigureMultiIssuerKeyDiscovery(
        JwtBearerOptions bearerOptions,
        JwtBearerAuthenticationOptions options,
        IReadOnlyList<string> additionalIssuers,
        Func<string, IConfigurationManager<OpenIdConnectConfiguration>>? configurationManagerFactory)
    {
        var requireHttpsMetadata = options.RequireHttpsMetadata ?? true;
        var factory = configurationManagerFactory ?? (issuer => new ConfigurationManager<OpenIdConnectConfiguration>(
            $"{issuer.TrimEnd('/')}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever { RequireHttps = requireHttpsMetadata }));

        var configurationManagers = new[] { options.Authority }
            .Concat(additionalIssuers)
            .Distinct(StringComparer.Ordinal)
            .ToDictionary(issuer => issuer, factory, StringComparer.Ordinal);

        // Reuse the primary issuer's manager as ASP.NET Core's own ConfigurationManager, instead of
        // letting JwtBearerHandler build a second, redundant one from Authority.
        bearerOptions.ConfigurationManager = configurationManagers[options.Authority];

        bearerOptions.Events ??= new JwtBearerEvents();
        var previousOnMessageReceived = bearerOptions.Events.OnMessageReceived;
        bearerOptions.Events.OnMessageReceived = async context =>
        {
            if (previousOnMessageReceived is not null)
            {
                await previousOnMessageReceived(context);
                if (context.Result is not null)
                {
                    return;
                }
            }

            // Warm every issuer's cached configuration asynchronously before the synchronous
            // IssuerSigningKeyResolver below runs later in this same request, so it reads an
            // already-completed Task instead of blocking a thread-pool thread on network I/O.
            await Task.WhenAll(configurationManagers.Values.Select(async manager =>
            {
                try
                {
                    await manager.GetConfigurationAsync(context.HttpContext.RequestAborted);
                }
                catch
                {
                    // Best-effort warm-up only. A manager that never fetched successfully simply
                    // contributes no signing keys below; validation fails naturally for its issuer.
                }
            }));
        };

        bearerOptions.TokenValidationParameters.IssuerSigningKeyResolver = (_, _, _, _) =>
        {
            var signingKeys = new List<SecurityKey>();
            foreach (var manager in configurationManagers.Values)
            {
                try
                {
                    var configuration = manager.GetConfigurationAsync(CancellationToken.None).GetAwaiter().GetResult();
                    signingKeys.AddRange(configuration.SigningKeys);
                }
                catch
                {
                    // Issuer's discovery endpoint has never succeeded; contributes no keys.
                }
            }

            return signingKeys;
        };
    }

    /// <summary>
    /// Adds a dev-only <c>OnAuthenticationFailed</c> handler that logs the validation exception when
    /// <see cref="IHostEnvironment.IsDevelopment"/> is true, chaining to (running before) any handler
    /// already configured on <paramref name="bearerOptions"/>.
    /// </summary>
    private static void ConfigureAuthenticationFailedDiagnostics(JwtBearerOptions bearerOptions)
    {
        bearerOptions.Events ??= new JwtBearerEvents();
        var previousOnAuthenticationFailed = bearerOptions.Events.OnAuthenticationFailed;
        bearerOptions.Events.OnAuthenticationFailed = async context =>
        {
            var environment = context.HttpContext.RequestServices.GetService<IHostEnvironment>();
            if (environment?.IsDevelopment() == true)
            {
                var logger = context.HttpContext.RequestServices.GetService<ILoggerFactory>()
                    ?.CreateLogger("SyntaxCircus.AspNetCore.Authentication.JwtBearer");
                logger?.LogDebug(context.Exception, "JWT bearer authentication failed.");
            }

            if (previousOnAuthenticationFailed is not null)
            {
                await previousOnAuthenticationFailed(context);
            }
        };
    }
}
