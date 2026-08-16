namespace SyntaxCircus.AspNetCore.Authentication.Tests;

public class ApiKeyValidationResultTests
{
    [Fact]
    public void Invalid_HasFalseIsValidAndNullClaims()
    {
        ApiKeyValidationResult.Invalid.IsValid.ShouldBeFalse();
        ApiKeyValidationResult.Invalid.Claims.ShouldBeNull();
    }

    [Fact]
    public void Valid_HasTrueIsValidAndRoundTripsClaims()
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, "test") };

        var result = ApiKeyValidationResult.Valid(claims);

        result.IsValid.ShouldBeTrue();
        result.Claims.ShouldBe(claims);
    }
}
