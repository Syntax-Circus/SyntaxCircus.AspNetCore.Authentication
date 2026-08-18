namespace SyntaxCircus.AspNetCore.Authentication.Tests;

public class ApiKeyAuthenticationExtensionsTests
{
    private static IConfiguration EmptyConfiguration()
        => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();

    [Fact]
    public void AddSyntaxCircusApiKey_NullServices_ThrowsArgumentNullException()
    {
        Should.Throw<ArgumentNullException>(() =>
            ApiKeyAuthenticationExtensions.AddSyntaxCircusApiKey(null!, EmptyConfiguration()));
    }

    [Fact]
    public void AddSyntaxCircusApiKey_NullConfiguration_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();

        Should.Throw<ArgumentNullException>(() => services.AddSyntaxCircusApiKey(null!));
    }

    [Fact]
    public void AddSyntaxCircusApiKey_NoValidatorPreRegistered_DefaultsToConstantApiKeyValidator()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusApiKey(EmptyConfiguration());

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IApiKeyValidator>().ShouldBeOfType<ConstantApiKeyValidator>();
    }

    [Fact]
    public void AddSyntaxCircusApiKey_CustomValidatorPreRegistered_IsPreserved()
    {
        var services = new ServiceCollection();
        var customValidator = Substitute.For<IApiKeyValidator>();
        services.AddSingleton(customValidator);

        services.AddSyntaxCircusApiKey(EmptyConfiguration());

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IApiKeyValidator>().ShouldBeSameAs(customValidator);
    }

    [Fact]
    public async Task AddSyntaxCircusApiKey_NoSchemeNameProvided_RegistersUnderDefaultSchemeName()
    {
        var services = new ServiceCollection();
        services.AddSyntaxCircusApiKey(EmptyConfiguration());

        using var provider = services.BuildServiceProvider();
        var schemeProvider = provider.GetRequiredService<IAuthenticationSchemeProvider>();

        (await schemeProvider.GetSchemeAsync(ApiKeyAuthenticationHandler.SchemeName)).ShouldNotBeNull();
    }

    [Fact]
    public async Task AddSyntaxCircusApiKey_CustomSchemeName_DefaultValidatorReadsNamedOptionsForThatScheme()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Auth:Worker:StaticKey"] = "worker-secret",
        }).Build();

        var services = new ServiceCollection();
        services.AddSyntaxCircusApiKey(configuration, "Auth:Worker", "WorkerApiKey");

        using var provider = services.BuildServiceProvider();
        var validator = provider.GetRequiredService<IApiKeyValidator>();

        (await validator.ValidateAsync("worker-secret", TestContext.Current.CancellationToken)).IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task AddSyntaxCircusApiKey_CalledTwiceWithDistinctSchemesAndKeyedValidators_EachSchemeUsesItsOwnValidator()
    {
        var validatorA = Substitute.For<IApiKeyValidator>();
        validatorA.ValidateAsync("key-a", Arg.Any<CancellationToken>())
            .Returns(ApiKeyValidationResult.Valid([new Claim(ClaimTypes.Name, "caller-a")]));
        validatorA.ValidateAsync(Arg.Is<string>(k => k != "key-a"), Arg.Any<CancellationToken>())
            .Returns(ApiKeyValidationResult.Invalid);

        var validatorB = Substitute.For<IApiKeyValidator>();
        validatorB.ValidateAsync("key-b", Arg.Any<CancellationToken>())
            .Returns(ApiKeyValidationResult.Valid([new Claim(ClaimTypes.Name, "caller-b")]));
        validatorB.ValidateAsync(Arg.Is<string>(k => k != "key-b"), Arg.Any<CancellationToken>())
            .Returns(ApiKeyValidationResult.Invalid);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddKeyedSingleton("SchemeA", validatorA);
        services.AddKeyedSingleton("SchemeB", validatorB);

        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Auth:A:HeaderName"] = "X-Api-Key-A",
            ["Auth:B:HeaderName"] = "X-Api-Key-B",
        }).Build();

        services.AddSyntaxCircusApiKey(configuration, "Auth:A", "SchemeA");
        services.AddSyntaxCircusApiKey(configuration, "Auth:B", "SchemeB");

        using var provider = services.BuildServiceProvider();
        var schemeProvider = provider.GetRequiredService<IAuthenticationSchemeProvider>();
        (await schemeProvider.GetSchemeAsync("SchemeA")).ShouldNotBeNull();
        (await schemeProvider.GetSchemeAsync("SchemeB")).ShouldNotBeNull();

        async Task<AuthenticateResult> AuthenticateAsync(string schemeName, string headerName, string headerValue)
        {
            var handler = provider.GetRequiredService<ApiKeyAuthenticationHandler>();
            var context = new DefaultHttpContext { RequestServices = provider };
            context.Request.Headers[headerName] = headerValue;
            var scheme = new AuthenticationScheme(schemeName, null, typeof(ApiKeyAuthenticationHandler));
            await handler.InitializeAsync(scheme, context);
            return await handler.AuthenticateAsync();
        }

        var resultA = await AuthenticateAsync("SchemeA", "X-Api-Key-A", "key-a");
        var resultB = await AuthenticateAsync("SchemeB", "X-Api-Key-B", "key-b");
        var crossSchemeResult = await AuthenticateAsync("SchemeB", "X-Api-Key-B", "key-a");

        resultA.Succeeded.ShouldBeTrue();
        resultA.Principal!.FindFirst(ClaimTypes.Name)?.Value.ShouldBe("caller-a");
        resultB.Succeeded.ShouldBeTrue();
        resultB.Principal!.FindFirst(ClaimTypes.Name)?.Value.ShouldBe("caller-b");
        crossSchemeResult.Succeeded.ShouldBeFalse();
    }
}
