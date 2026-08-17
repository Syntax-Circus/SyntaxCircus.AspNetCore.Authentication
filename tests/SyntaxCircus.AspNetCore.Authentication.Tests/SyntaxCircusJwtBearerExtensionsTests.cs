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

    [Fact]
    public void AddSyntaxCircusJwtBearer_RequireHttpsMetadataConfiguredFalse_SetsRequireHttpsMetadata()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:RequireHttpsMetadata"] = "false",
        }));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.RequireHttpsMetadata.ShouldBeFalse();
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_RequireHttpsMetadataNotConfigured_LeavesAspNetCoreDefault()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom([]));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.RequireHttpsMetadata.ShouldBeTrue();
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_MapInboundClaimsConfiguredFalse_SetsMapInboundClaims()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:MapInboundClaims"] = "false",
        }));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.MapInboundClaims.ShouldBeFalse();
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_MapInboundClaimsNotConfigured_LeavesAspNetCoreDefault()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom([]));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.MapInboundClaims.ShouldBeTrue();
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_RoleAndNameClaimTypeConfigured_SetsTokenValidationParameters()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:RoleClaimType"] = "roles",
            ["Authentication:JwtBearer:NameClaimType"] = "username",
        }));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.TokenValidationParameters.RoleClaimType.ShouldBe("roles");
        options.TokenValidationParameters.NameClaimType.ShouldBe("username");
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_RoleAndNameClaimTypeNotConfigured_LeavesDefaults()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom([]));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.TokenValidationParameters.RoleClaimType.ShouldBe(ClaimTypes.Role);
        options.TokenValidationParameters.NameClaimType.ShouldBe(ClaimTypes.Name);
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_LogAuthenticationFailuresInDevelopmentDefault_LeavesDefaultEventsUntouched()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom([]));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        // JwtBearerOptions.Events itself defaults to a non-null instance with no-op delegates;
        // asserting against that default (rather than null) proves we didn't touch it when opted out.
        options.Events!.OnAuthenticationFailed.ShouldBe(new JwtBearerEvents().OnAuthenticationFailed);
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_LogAuthenticationFailuresInDevelopmentEnabled_AddsHandler()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:LogAuthenticationFailuresInDevelopment"] = "true",
        }));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.Events!.OnAuthenticationFailed.ShouldNotBe(new JwtBearerEvents().OnAuthenticationFailed);
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_TrustedIssuersOnlyRepeatsAuthority_DoesNotAddResolver()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:Authority"] = "https://auth.example.com",
            ["Authentication:JwtBearer:TrustedIssuers:0"] = "https://auth.example.com",
        }));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        // ConfigurationManager itself is still non-null here — ASP.NET Core's own
        // JwtBearerPostConfigureOptions builds one from Authority regardless — but the resolver is
        // the signal that our multi-issuer merge logic did (or didn't) engage.
        options.TokenValidationParameters.IssuerSigningKeyResolver.ShouldBeNull();
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_TrustedIssuersDistinctFromAuthority_AddsResolverAndConfigurationManager()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:Authority"] = "https://auth.example.com/app-a",
            ["Authentication:JwtBearer:TrustedIssuers:0"] = "https://auth.example.com/app-b",
        }));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.TokenValidationParameters.IssuerSigningKeyResolver.ShouldNotBeNull();
        options.ConfigurationManager.ShouldNotBeNull();
    }

    [Fact]
    public void AddSyntaxCircusJwtBearer_EmptyAuthorityWithTrustedIssuers_DoesNotThrow()
    {
        var services = new ServiceCollection();

        Should.NotThrow(() => services.AddSyntaxCircusJwtBearer(ConfigurationFrom(new Dictionary<string, string?>
        {
            ["Authentication:JwtBearer:TrustedIssuers:0"] = "https://auth.example.com/app-b",
        })));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.TokenValidationParameters.IssuerSigningKeyResolver.ShouldBeNull();
        options.ConfigurationManager.ShouldBeNull();
    }
}
