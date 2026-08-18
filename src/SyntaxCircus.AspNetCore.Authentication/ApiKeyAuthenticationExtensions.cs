namespace SyntaxCircus.AspNetCore.Authentication;

public static class ApiKeyAuthenticationExtensions
{
    /// <summary>
    /// Registers API-key authentication under <paramref name="schemeName"/> (defaulting to
    /// <see cref="ApiKeyAuthenticationHandler.SchemeName"/>). Uses <see cref="ConstantApiKeyValidator"/>
    /// (single configured key) unless you register your own <see cref="IApiKeyValidator"/> first —
    /// e.g. a DB-backed hashed-key lookup.
    /// </summary>
    /// <remarks>
    /// Call this more than once with distinct <paramref name="schemeName"/>/<paramref name="sectionName"/>
    /// pairs to register independent API-key concerns in the same app (distinct header names, distinct
    /// config). Only the first call's <see cref="ConstantApiKeyValidator"/> registration is used by the
    /// unkeyed <see cref="IApiKeyValidator"/> slot; every additional scheme that needs its own validator
    /// (built-in or custom) should register it keyed by its scheme name — e.g.
    /// <c>services.AddKeyedSingleton&lt;IApiKeyValidator, MyValidator&gt;(schemeName)</c> — before calling
    /// this method. See the API key section of the package README for a worked multi-scheme example.
    /// </remarks>
    public static AuthenticationBuilder AddSyntaxCircusApiKey(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ApiKeyAuthenticationOptions.SectionName,
        string schemeName = ApiKeyAuthenticationHandler.SchemeName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.TryAddSingleton<IApiKeyValidator>(sp =>
            new ConstantApiKeyValidator(sp.GetRequiredService<IOptionsMonitor<ApiKeyAuthenticationOptions>>(), schemeName));
        services.Configure<ApiKeyAuthenticationOptions>(configuration.GetSection(sectionName));

        return services.AddAuthentication()
            .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
                schemeName,
                configureOptions: opts => configuration.GetSection(sectionName).Bind(opts));
    }
}
