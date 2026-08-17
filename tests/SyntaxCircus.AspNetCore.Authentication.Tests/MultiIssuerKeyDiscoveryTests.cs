using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace SyntaxCircus.AspNetCore.Authentication.Tests;

/// <summary>
/// End-to-end coverage for the multi-issuer key-discovery fan-out described in
/// docs/enhancements/2026-08-17-multi-issuer-key-discovery.md: a token signed by a
/// <c>TrustedIssuers</c> entry that is a genuinely distinct OIDC application (its own JWKS, not
/// just an alternate issuer string for <c>Authority</c>'s keys) must validate.
/// </summary>
public class MultiIssuerKeyDiscoveryTests
{
    private const string IssuerA = "https://issuer-a.test";
    private const string IssuerB = "https://issuer-b.test";
    private const string Audience = "test-aud";

    [Fact]
    public async Task MultiIssuer_TokenSignedByNonPrimaryIssuer_Validates()
    {
        var issuerAKey = CreateSigningKey("kid-a");
        var issuerBKey = CreateSigningKey("kid-b");
        using var httpClient = CreateStubHttpClient(
            (IssuerA, issuerAKey.jsonWebKey),
            (IssuerB, issuerBKey.jsonWebKey));

        var tokenValidationParameters = BuildTokenValidationParameters(httpClient);

        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = IssuerB,
            Audience = Audience,
            SigningCredentials = new SigningCredentials(issuerBKey.securityKey, SecurityAlgorithms.RsaSha256),
            Expires = DateTime.UtcNow.AddMinutes(5),
        });

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, tokenValidationParameters);

        result.IsValid.ShouldBeTrue(result.Exception?.ToString());
    }

    [Fact]
    public async Task MultiIssuer_TokenSignedByUnregisteredKey_FailsValidation()
    {
        var issuerAKey = CreateSigningKey("kid-a");
        var issuerBKey = CreateSigningKey("kid-b");
        var forgedKey = CreateSigningKey("kid-forged");
        using var httpClient = CreateStubHttpClient(
            (IssuerA, issuerAKey.jsonWebKey),
            (IssuerB, issuerBKey.jsonWebKey));

        var tokenValidationParameters = BuildTokenValidationParameters(httpClient);

        // Issuer claim is valid (issuer-b), but the signing key was never published by any
        // configured issuer's JWKS — signature verification must fail.
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = IssuerB,
            Audience = Audience,
            SigningCredentials = new SigningCredentials(forgedKey.securityKey, SecurityAlgorithms.RsaSha256),
            Expires = DateTime.UtcNow.AddMinutes(5),
        });

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, tokenValidationParameters);

        result.IsValid.ShouldBeFalse();
    }

    private static TokenValidationParameters BuildTokenValidationParameters(HttpClient httpClient)
    {
        var services = new ServiceCollection();
        SyntaxCircusJwtBearerExtensions.AddSyntaxCircusJwtBearer(
            services,
            ConfigurationFrom(new Dictionary<string, string?>
            {
                ["Authentication:JwtBearer:Authority"] = IssuerA,
                ["Authentication:JwtBearer:TrustedIssuers:0"] = IssuerB,
                ["Authentication:JwtBearer:Audiences:0"] = Audience,
            }),
            JwtBearerAuthenticationOptions.SectionName,
            issuer => new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{issuer.TrimEnd('/')}/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(httpClient)));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        return options.TokenValidationParameters;
    }

    private static IConfiguration ConfigurationFrom(Dictionary<string, string?> values)
        => new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    private static (RsaSecurityKey securityKey, string jsonWebKey) CreateSigningKey(string keyId)
    {
        var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);
        var n = Base64UrlEncoder.Encode(parameters.Modulus);
        var e = Base64UrlEncoder.Encode(parameters.Exponent);
        var jwk = $$"""{"kty":"RSA","kid":"{{keyId}}","use":"sig","alg":"RS256","n":"{{n}}","e":"{{e}}"}""";

        return (new RsaSecurityKey(rsa) { KeyId = keyId }, jwk);
    }

    private static HttpClient CreateStubHttpClient(params (string issuer, string jwk)[] issuers)
    {
        var responsesByUri = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (issuer, jwk) in issuers)
        {
            responsesByUri[$"{issuer}/.well-known/openid-configuration"] =
                $$"""{"issuer":"{{issuer}}","jwks_uri":"{{issuer}}/jwks"}""";
            responsesByUri[$"{issuer}/jwks"] = $$"""{"keys":[{{jwk}}]}""";
        }

        return new HttpClient(new StubOidcHttpMessageHandler(responsesByUri));
    }

    private sealed class StubOidcHttpMessageHandler(IReadOnlyDictionary<string, string> jsonByUri) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!jsonByUri.TryGetValue(request.RequestUri!.ToString(), out var json))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            });
        }
    }
}
