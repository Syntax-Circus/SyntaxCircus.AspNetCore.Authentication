namespace SyntaxCircus.AspNetCore.Authentication.Tests;

public class ApiKeyAuthenticationOptionsTests
{
    [Fact]
    public void Defaults_AreExpected()
    {
        var options = new ApiKeyAuthenticationOptions();

        options.HeaderName.ShouldBe("X-Api-Key");
        options.StaticKey.ShouldBe(string.Empty);
    }

    [Fact]
    public void SectionName_IsAuthenticationApiKey()
    {
        ApiKeyAuthenticationOptions.SectionName.ShouldBe("Authentication:ApiKey");
    }
}
