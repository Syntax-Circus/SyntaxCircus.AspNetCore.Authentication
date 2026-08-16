using System.Security.Claims;

namespace SyntaxCircus.AspNetCore.Authentication;

/// <summary>Validates an incoming API key and, if valid, supplies the claims to build a principal from.</summary>
public interface IApiKeyValidator
{
    Task<ApiKeyValidationResult> ValidateAsync(string apiKey, CancellationToken cancellationToken = default);
}

public sealed record ApiKeyValidationResult(bool IsValid, IReadOnlyList<Claim>? Claims = null)
{
    public static ApiKeyValidationResult Invalid { get; } = new(false);

    public static ApiKeyValidationResult Valid(IReadOnlyList<Claim> claims) => new(true, claims);
}
