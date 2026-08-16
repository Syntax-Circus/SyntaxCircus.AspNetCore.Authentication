using System.Text;

namespace SyntaxCircus.AspNetCore.Authentication.Tests;

public class JwtSchemeSelectorTests
{
    private static string Base64UrlEncode(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string TokenWithHeader(string headerJson) => $"{Base64UrlEncode(headerJson)}.payload.signature";

    private static DefaultHttpContext ContextWithAuthorizationHeader(string? headerValue)
    {
        var context = new DefaultHttpContext();
        if (headerValue is not null)
        {
            context.Request.Headers.Authorization = headerValue;
        }

        return context;
    }

    private static JwtBearerAuthenticationOptions OptionsWithDeviceTokenEnabled(bool enabled = true)
        => new() { DeviceToken = new JwtBearerAuthenticationOptions.DeviceTokenOptions { Enabled = enabled } };

    [Fact]
    public void SelectScheme_NullContext_ThrowsArgumentNullException()
    {
        Should.Throw<ArgumentNullException>(() => JwtSchemeSelector.SelectScheme(null!, OptionsWithDeviceTokenEnabled()));
    }

    [Fact]
    public void SelectScheme_NullOptions_ThrowsArgumentNullException()
    {
        Should.Throw<ArgumentNullException>(() => JwtSchemeSelector.SelectScheme(ContextWithAuthorizationHeader(null), null!));
    }

    [Fact]
    public void SelectScheme_DeviceTokenDisabled_AlwaysReturnsDefaultScheme()
    {
        var context = ContextWithAuthorizationHeader($"Bearer {TokenWithHeader("""{"alg":"HS256"}""")}");

        var scheme = JwtSchemeSelector.SelectScheme(context, OptionsWithDeviceTokenEnabled(enabled: false));

        scheme.ShouldBe(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public void SelectScheme_NoAuthorizationHeader_ReturnsDefaultScheme()
    {
        var context = ContextWithAuthorizationHeader(null);

        var scheme = JwtSchemeSelector.SelectScheme(context, OptionsWithDeviceTokenEnabled());

        scheme.ShouldBe(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public void SelectScheme_HeaderDoesNotStartWithBearer_ReturnsDefaultScheme()
    {
        var context = ContextWithAuthorizationHeader("Basic dXNlcjpwYXNz");

        var scheme = JwtSchemeSelector.SelectScheme(context, OptionsWithDeviceTokenEnabled());

        scheme.ShouldBe(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public void SelectScheme_LowercaseBearerPrefix_StillRecognized()
    {
        var context = ContextWithAuthorizationHeader($"bearer {TokenWithHeader("""{"alg":"HS256"}""")}");

        var scheme = JwtSchemeSelector.SelectScheme(context, OptionsWithDeviceTokenEnabled());

        scheme.ShouldBe(SyntaxCircusJwtBearerExtensions.DeviceScheme);
    }

    [Fact]
    public void SelectScheme_Hs256Token_ReturnsDeviceScheme()
    {
        var context = ContextWithAuthorizationHeader($"Bearer {TokenWithHeader("""{"alg":"HS256"}""")}");

        var scheme = JwtSchemeSelector.SelectScheme(context, OptionsWithDeviceTokenEnabled());

        scheme.ShouldBe(SyntaxCircusJwtBearerExtensions.DeviceScheme);
    }

    [Fact]
    public void SelectScheme_Rs256Token_ReturnsDefaultScheme()
    {
        var context = ContextWithAuthorizationHeader($"Bearer {TokenWithHeader("""{"alg":"RS256"}""")}");

        var scheme = JwtSchemeSelector.SelectScheme(context, OptionsWithDeviceTokenEnabled());

        scheme.ShouldBe(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public void SelectScheme_MalformedBase64Header_ReturnsDefaultScheme()
    {
        var context = ContextWithAuthorizationHeader("Bearer not-valid-base64!!!.payload.signature");

        var scheme = JwtSchemeSelector.SelectScheme(context, OptionsWithDeviceTokenEnabled());

        scheme.ShouldBe(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public void SelectScheme_ValidBase64ButNotJson_ReturnsDefaultScheme()
    {
        var notJson = Convert.ToBase64String(Encoding.UTF8.GetBytes("not json at all")).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var context = ContextWithAuthorizationHeader($"Bearer {notJson}.payload.signature");

        var scheme = JwtSchemeSelector.SelectScheme(context, OptionsWithDeviceTokenEnabled());

        scheme.ShouldBe(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public void SelectScheme_EmptyFirstSegment_ReturnsDefaultScheme()
    {
        var context = ContextWithAuthorizationHeader("Bearer .payload.signature");

        var scheme = JwtSchemeSelector.SelectScheme(context, OptionsWithDeviceTokenEnabled());

        scheme.ShouldBe(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public void SelectScheme_HeaderMissingAlgProperty_ReturnsDefaultScheme()
    {
        var context = ContextWithAuthorizationHeader($"Bearer {TokenWithHeader("""{"typ":"JWT"}""")}");

        var scheme = JwtSchemeSelector.SelectScheme(context, OptionsWithDeviceTokenEnabled());

        scheme.ShouldBe(JwtBearerDefaults.AuthenticationScheme);
    }
}
