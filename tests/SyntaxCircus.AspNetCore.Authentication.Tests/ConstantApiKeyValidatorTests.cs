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
}
