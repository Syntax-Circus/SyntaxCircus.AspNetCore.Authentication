using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SyntaxCircus.AspNetCore.Authentication;

/// <summary>
/// Validates against a single configured key using a constant-time comparison — the simplest
/// option, one shared key for the whole caller population. Register your own
/// <see cref="IApiKeyValidator"/> instead for per-caller or DB-backed/hashed-key validation.
/// </summary>
public sealed class ConstantApiKeyValidator(IOptions<ApiKeyAuthenticationOptions> options) : IApiKeyValidator
{
    public Task<ApiKeyValidationResult> ValidateAsync(string apiKey, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);

        var configuredKey = options.Value.StaticKey;
        var isValid = !string.IsNullOrEmpty(configuredKey)
            && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(apiKey), Encoding.UTF8.GetBytes(configuredKey));

        return Task.FromResult(isValid
            ? ApiKeyValidationResult.Valid([new Claim(ClaimTypes.AuthenticationMethod, "ApiKey")])
            : ApiKeyValidationResult.Invalid);
    }
}
