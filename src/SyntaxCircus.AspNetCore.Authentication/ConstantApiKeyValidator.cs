using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SyntaxCircus.AspNetCore.Authentication;

/// <summary>
/// Validates against a single configured key using a constant-time comparison — the simplest
/// option, one shared key for the whole caller population. Register your own
/// <see cref="IApiKeyValidator"/> instead for per-caller or DB-backed/hashed-key validation.
/// </summary>
public sealed class ConstantApiKeyValidator : IApiKeyValidator
{
    private readonly Func<ApiKeyAuthenticationOptions> _resolveOptions;

    public ConstantApiKeyValidator(IOptions<ApiKeyAuthenticationOptions> options)
        : this(() => options.Value)
    {
    }

    /// <summary>
    /// Used internally by <see cref="ApiKeyAuthenticationExtensions.AddSyntaxCircusApiKey"/> so the
    /// default validator reads its own scheme's named options (via <see cref="IOptionsMonitor{TOptions}.Get(string?)"/>)
    /// rather than the unnamed options instance — which only reflects whichever scheme's config section
    /// was configured last when multiple schemes are registered.
    /// </summary>
    internal ConstantApiKeyValidator(IOptionsMonitor<ApiKeyAuthenticationOptions> optionsMonitor, string schemeName)
        : this(() => optionsMonitor.Get(schemeName))
    {
    }

    private ConstantApiKeyValidator(Func<ApiKeyAuthenticationOptions> resolveOptions)
    {
        _resolveOptions = resolveOptions;
    }

    public Task<ApiKeyValidationResult> ValidateAsync(string apiKey, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);

        var configuredKey = _resolveOptions().StaticKey;
        var isValid = !string.IsNullOrEmpty(configuredKey)
            && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(apiKey), Encoding.UTF8.GetBytes(configuredKey));

        return Task.FromResult(isValid
            ? ApiKeyValidationResult.Valid([new Claim(ClaimTypes.AuthenticationMethod, "ApiKey")])
            : ApiKeyValidationResult.Invalid);
    }
}
