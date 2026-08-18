namespace SyntaxCircus.AspNetCore.Authentication.Tests;

public class ConstantApiKeyValidatorTests
{
    private static ConstantApiKeyValidator CreateValidator(string configuredKey)
        => new(Options.Create(new ApiKeyAuthenticationOptions { StaticKey = configuredKey }));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ValidateAsync_BlankApiKey_ThrowsArgumentException(string apiKey)
    {
        var validator = CreateValidator("secret");

        await Should.ThrowAsync<ArgumentException>(() => validator.ValidateAsync(apiKey, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ValidateAsync_EmptyConfiguredKey_AlwaysInvalid()
    {
        var validator = CreateValidator(string.Empty);

        var result = await validator.ValidateAsync("anything", TestContext.Current.CancellationToken);

        result.IsValid.ShouldBeFalse();
    }

    [Fact]
    public async Task ValidateAsync_MatchingKey_ReturnsValidWithClaim()
    {
        var validator = CreateValidator("secret");

        var result = await validator.ValidateAsync("secret", TestContext.Current.CancellationToken);

        result.IsValid.ShouldBeTrue();
        result.Claims.ShouldNotBeNull();
        result.Claims!.Single().Type.ShouldBe(ClaimTypes.AuthenticationMethod);
        result.Claims!.Single().Value.ShouldBe("ApiKey");
    }

    [Fact]
    public async Task ValidateAsync_DifferentKeySameLength_ReturnsInvalid()
    {
        var validator = CreateValidator("secret");

        var result = await validator.ValidateAsync("SECRET", TestContext.Current.CancellationToken);

        result.IsValid.ShouldBeFalse();
    }

    [Fact]
    public async Task ValidateAsync_DifferentKeyDifferentLength_ReturnsInvalid()
    {
        var validator = CreateValidator("secret");

        var result = await validator.ValidateAsync("nope", TestContext.Current.CancellationToken);

        result.IsValid.ShouldBeFalse();
    }

    [Fact]
    public async Task ValidateAsync_InternalSchemeAwareConstructor_ReadsNamedOptions()
    {
        var optionsMonitor = Substitute.For<IOptionsMonitor<ApiKeyAuthenticationOptions>>();
        optionsMonitor.Get("SchemeA").Returns(new ApiKeyAuthenticationOptions { StaticKey = "a-secret" });
        optionsMonitor.Get("SchemeB").Returns(new ApiKeyAuthenticationOptions { StaticKey = "b-secret" });

        var validatorA = new ConstantApiKeyValidator(optionsMonitor, "SchemeA");
        var validatorB = new ConstantApiKeyValidator(optionsMonitor, "SchemeB");

        (await validatorA.ValidateAsync("a-secret", TestContext.Current.CancellationToken)).IsValid.ShouldBeTrue();
        (await validatorA.ValidateAsync("b-secret", TestContext.Current.CancellationToken)).IsValid.ShouldBeFalse();
        (await validatorB.ValidateAsync("b-secret", TestContext.Current.CancellationToken)).IsValid.ShouldBeTrue();
        (await validatorB.ValidateAsync("a-secret", TestContext.Current.CancellationToken)).IsValid.ShouldBeFalse();
    }
}
