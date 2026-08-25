using System.Text.Json;

namespace SyntaxCircus.AspNetCore.Authentication;

/// <summary>
/// Registers a policy scheme that routes opaque bearer credentials and JWT bearer credentials to
/// independently registered authentication handlers.
/// </summary>
public static class BearerCompositeAuthenticationExtensions
{
    /// <summary>
    /// Adds a policy scheme that selects <paramref name="jwtScheme"/> only for bearer credentials
    /// with a readable JWT header. All other bearer credentials are delegated to
    /// <paramref name="opaqueBearerScheme"/>.
    /// </summary>
    public static AuthenticationBuilder AddSyntaxCircusCompositeBearer(
        this AuthenticationBuilder authenticationBuilder,
        string opaqueBearerScheme,
        string jwtScheme = JwtBearerDefaults.AuthenticationScheme,
        string schemeName = "SyntaxCircusCompositeBearer")
    {
        ArgumentNullException.ThrowIfNull(authenticationBuilder);
        ArgumentException.ThrowIfNullOrWhiteSpace(opaqueBearerScheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(jwtScheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(schemeName);

        return authenticationBuilder.AddPolicyScheme(schemeName, schemeName, options =>
        {
            options.ForwardDefaultSelector = context => SelectScheme(context, opaqueBearerScheme, jwtScheme);
        });
    }

    /// <summary>
    /// Selects the registered JWT scheme for a syntactically readable JWT bearer credential and
    /// the opaque bearer scheme for every other credential.
    /// </summary>
    public static string SelectScheme(HttpContext context, string opaqueBearerScheme, string jwtScheme)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(opaqueBearerScheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(jwtScheme);

        var credential = GetBearerCredential(context.Request);
        return IsJwt(credential) ? jwtScheme : opaqueBearerScheme;
    }

    /// <summary>
    /// Gets the non-empty credential from an <c>Authorization: Bearer</c> header, or
    /// <see langword="null"/> when the request has no bearer credential.
    /// </summary>
    public static string? GetBearerCredential(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var authorization = request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var credential = authorization["Bearer ".Length..].Trim();
        return string.IsNullOrWhiteSpace(credential) ? null : credential;
    }

    private static bool IsJwt(string? credential)
    {
        if (string.IsNullOrWhiteSpace(credential))
        {
            return false;
        }

        var parts = credential.Split('.');
        if (parts.Length != 3 || string.IsNullOrWhiteSpace(parts[0]))
        {
            return false;
        }

        try
        {
            var header = parts[0].Replace('-', '+').Replace('_', '/');
            header = header.PadRight(header.Length + ((4 - (header.Length % 4)) % 4), '=');
            using var document = JsonDocument.Parse(Convert.FromBase64String(header));
            return document.RootElement.TryGetProperty("alg", out var algorithm)
                && !string.IsNullOrWhiteSpace(algorithm.GetString());
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return false;
        }
    }
}
