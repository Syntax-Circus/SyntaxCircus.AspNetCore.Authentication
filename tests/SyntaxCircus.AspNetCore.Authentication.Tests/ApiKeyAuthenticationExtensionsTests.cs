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
}
