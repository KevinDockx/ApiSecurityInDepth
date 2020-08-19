namespace ApiSecurityInDepth.Client.Services
{
    public interface ITokenGenerator
    {
        string CreateSignedToken(string clientId, string audience);
    }
}