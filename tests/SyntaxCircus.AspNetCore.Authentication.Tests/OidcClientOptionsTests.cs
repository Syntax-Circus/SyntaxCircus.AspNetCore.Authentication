namespace SyntaxCircus.AspNetCore.Authentication.Tests;

public class OidcClientOptionsTests
{
    [Fact]
    public void Defaults_AreExpected()
    {
        var options = new OidcClientOptions();

        options.Authority.ShouldBe(string.Empty);
        options.ClientId.ShouldBe(string.Empty);
        options.ClientSecret.ShouldBe(string.Empty);
        options.Scopes.ShouldBe(["openid", "profile", "email"]);
    }

    [Fact]
    public void Properties_AreSettable()
    {
        var options = new OidcClientOptions
        {
            Authority = "https://auth.example.com",
            ClientId = "client",
            ClientSecret = "secret",
            Scopes = ["openid"],
        };

        options.Authority.ShouldBe("https://auth.example.com");
        options.ClientId.ShouldBe("client");
        options.ClientSecret.ShouldBe("secret");
        options.Scopes.ShouldBe(["openid"]);
    }
}
