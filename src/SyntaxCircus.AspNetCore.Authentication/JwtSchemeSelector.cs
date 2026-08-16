using System.Text.Json;

namespace SyntaxCircus.AspNetCore.Authentication;

/// <summary>
/// Picks which registered JWT scheme should handle the current request by sniffing the incoming
/// token's <c>alg</c> header — HS256 (symmetric) means one of our self-issued device tokens;
/// anything else (typically RS256 from an OIDC provider) means the primary OIDC-backed scheme.
/// </summary>
internal static class JwtSchemeSelector
{
    public static string SelectScheme(HttpContext context, JwtBearerAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(options);

        if (!options.DeviceToken.Enabled)
        {
            return JwtBearerDefaults.AuthenticationScheme;
        }

        var authorizationHeader = context.Request.Headers.Authorization.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(authorizationHeader) || !authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return JwtBearerDefaults.AuthenticationScheme;
        }

        var token = authorizationHeader["Bearer ".Length..].Trim();
        var algorithm = TryReadHeaderAlgorithm(token);

        return string.Equals(algorithm, "HS256", StringComparison.Ordinal)
            ? SyntaxCircusJwtBearerExtensions.DeviceScheme
            : JwtBearerDefaults.AuthenticationScheme;
    }

    private static string? TryReadHeaderAlgorithm(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 1 || string.IsNullOrWhiteSpace(parts[0]))
        {
            return null;
        }

        try
        {
            var header = parts[0].Replace('-', '+').Replace('_', '/');
            header = header.PadRight(header.Length + ((4 - (header.Length % 4)) % 4), '=');
            using var document = JsonDocument.Parse(Convert.FromBase64String(header));
            return document.RootElement.TryGetProperty("alg", out var alg) ? alg.GetString() : null;
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return null;
        }
    }
}
