namespace SyntaxCircus.AspNetCore.Authentication;

public static class ApiKeyAuthenticationExtensions
{
    /// <summary>
    /// Registers API-key authentication under scheme name <see cref="ApiKeyAuthenticationHandler.SchemeName"/>.
    /// Uses <see cref="ConstantApiKeyValidator"/> (single configured key) unless you register your
    /// own <see cref="IApiKeyValidator"/> first — e.g. a DB-backed hashed-key lookup.
    /// </summary>
    public static AuthenticationBuilder AddSyntaxCircusApiKey(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = ApiKeyAuthenticationOptions.SectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.TryAddSingleton<IApiKeyValidator, ConstantApiKeyValidator>();
        services.Configure<ApiKeyAuthenticationOptions>(configuration.GetSection(sectionName));

        return services.AddAuthentication()
            .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
                ApiKeyAuthenticationHandler.SchemeName,
                configureOptions: opts => configuration.GetSection(sectionName).Bind(opts));
    }
}
