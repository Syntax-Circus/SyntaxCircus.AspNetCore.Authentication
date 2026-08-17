namespace SyntaxCircus.AspNetCore.Authentication.Tests;

public class JwtBearerAuthenticationOptionsTests
{
    [Fact]
    public void Defaults_AreExpected()
    {
        var options = new JwtBearerAuthenticationOptions();

        options.Authority.ShouldBe(string.Empty);
        options.Audiences.ShouldBeEmpty();
        options.TrustedIssuers.ShouldBeEmpty();
        options.RequireHttpsMetadata.ShouldBeNull();
        options.MapInboundClaims.ShouldBeNull();
        options.RoleClaimType.ShouldBeNull();
        options.NameClaimType.ShouldBeNull();
        options.LogAuthenticationFailuresInDevelopment.ShouldBeFalse();
        options.DeviceToken.ShouldNotBeNull();
    }

    [Fact]
    public void SectionName_IsAuthenticationJwtBearer()
    {
        JwtBearerAuthenticationOptions.SectionName.ShouldBe("Authentication:JwtBearer");
    }

    [Fact]
    public void DeviceTokenOptions_Defaults_AreExpected()
    {
        var options = new JwtBearerAuthenticationOptions.DeviceTokenOptions();

        options.Enabled.ShouldBeFalse();
        options.SigningKey.ShouldBe(string.Empty);
        options.Issuer.ShouldBe(string.Empty);
        options.Audience.ShouldBe(string.Empty);
    }
}
