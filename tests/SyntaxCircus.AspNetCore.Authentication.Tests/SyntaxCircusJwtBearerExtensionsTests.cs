namespace SyntaxCircus.AspNetCore.Authentication.Tests;

public class SyntaxCircusJwtBearerExtensionsTests
{
    private static IConfiguration ConfigurationFrom(Dictionary<string, string?> values)
        => new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    [Fact]
    public void AddSyntaxCircusJwtBearer_NullServices_ThrowsArgumentNullException()
    {
        Should.Throw<ArgumentNullException>(() =>
            SyntaxCircusJwtBearerExtensions.AddSyntaxCircusJwtBearer(null!, ConfigurationFrom([])));
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_NullConfiguration_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();

        Should.Throw<ArgumentNullException>(() => services.AddSyntaxCircusJwtBearer(null!));
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_DeviceTokenDisabled_DefaultSchemeIsPrimary()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:Authority"] = "https://auth.example.com",
        }));

        using var provider = services.BuildServiceProvider();
        var defaultScheme = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value.DefaultScheme;

        defaultScheme.ShouldBe(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public async Task AddSyntaxCircusJwtBearer_DeviceTokenDisabled_OnlyPrimarySchemeRegistered()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom([]));

        using var provider = services.BuildServiceProvider();
        var schemeProvider = provider.GetRequiredService<IAuthenticationSchemeProvider>();

        (await schemeProvider.GetSchemeAsync(SyntaxCircusJwtBearerExtensions.DeviceScheme)).ShouldBeNull();
        (await schemeProvider.GetSchemeAsync(SyntaxCircusJwtBearerExtensions.PolicyScheme)).ShouldBeNull();
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_DeviceTokenEnabled_DefaultSchemeIsPolicyScheme()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:DeviceToken:Enabled"] = "true",
            ["Authentication:JwtBearer:DeviceToken:SigningKey"] = "a-sufficiently-long-signing-key-for-hs256",
            ["Authentication:JwtBearer:DeviceToken:Issuer"] = "issuer",
            ["Authentication:JwtBearer:DeviceToken:Audience"] = "audience",
        }));

        using var provider = services.BuildServiceProvider();
        var defaultScheme = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value.DefaultScheme;

        defaultScheme.ShouldBe(SyntaxCircusJwtBearerExtensions.PolicyScheme);
    }

    [Fact]
    public async Task AddSyntaxCircusJwtBearer_DeviceTokenEnabled_AllThreeSchemesRegistered()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:DeviceToken:Enabled"] = "true",
            ["Authentication:JwtBearer:DeviceToken:SigningKey"] = "a-sufficiently-long-signing-key-for-hs256",
        }));

        using var provider = services.BuildServiceProvider();
        var schemeProvider = provider.GetRequiredService<IAuthenticationSchemeProvider>();

        (await schemeProvider.GetSchemeAsync(JwtBearerDefaults.AuthenticationScheme)).ShouldNotBeNull();
        (await schemeProvider.GetSchemeAsync(SyntaxCircusJwtBearerExtensions.DeviceScheme)).ShouldNotBeNull();
        (await schemeProvider.GetSchemeAsync(SyntaxCircusJwtBearerExtensions.PolicyScheme)).ShouldNotBeNull();
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_AudiencesConfigured_SetsValidAudiences()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:Audiences:0"] = "aud1",
            ["Authentication:JwtBearer:Audiences:1"] = "aud2",
        }));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.TokenValidationParameters.ValidAudiences.ShouldBe(["aud1", "aud2"]);
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_NoAudiencesConfigured_LeavesValidAudiencesUnset()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom([]));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.TokenValidationParameters.ValidAudiences.ShouldBeNull();
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_TrustedIssuersConfigured_SetsValidIssuers()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:TrustedIssuers:0"] = "issuer1",
        }));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.TokenValidationParameters.ValidIssuers.ShouldBe(["issuer1"]);
    }
}
