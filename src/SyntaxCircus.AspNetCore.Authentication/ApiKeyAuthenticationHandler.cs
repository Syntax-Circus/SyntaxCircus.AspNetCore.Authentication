using System.Security.Claims;
using System.Text.Encodings.Web;

namespace SyntaxCircus.AspNetCore.Authentication;

public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IApiKeyValidator validator)
    : AuthenticationHandler<ApiKeyAuthenticationOptions>(options, logger, encoder)
{
    public const string SchemeName = "ApiKey";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(Options.HeaderName, out var headerValues))
        {
            return AuthenticateResult.NoResult();
        }

        var apiKey = headerValues.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return AuthenticateResult.NoResult();
        }

        var effectiveValidator = validator;
        if (Context.RequestServices is IKeyedServiceProvider keyedProvider)
        {
            effectiveValidator = keyedProvider.GetKeyedService<IApiKeyValidator>(Scheme.Name) ?? validator;
        }

        var result = await effectiveValidator.ValidateAsync(apiKey, Context.RequestAborted).ConfigureAwait(false);
        if (!result.IsValid)
        {
            return AuthenticateResult.Fail("Invalid API key.");
        }

        var identity = new ClaimsIdentity(result.Claims ?? [], Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}
