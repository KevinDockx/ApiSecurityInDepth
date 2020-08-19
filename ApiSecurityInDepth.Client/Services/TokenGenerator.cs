using IdentityModel;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace ApiSecurityInDepth.Client.Services
{
    public class TokenGenerator : ITokenGenerator
    {
        private readonly IConfiguration _configuration;

        public TokenGenerator(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }
            
        /// <summary>
        /// Create a signed token (used for client auth)
        /// </summary>
        /// <param name="clientId">The client id</param>
        /// <param name="audience">The audience (typically the token endpoint)</param>
        /// <returns></returns>
        public string CreateSignedToken(string clientId, string audience)
        {
            var certificate = new X509Certificate2("client.pfx", "password");
            var now = DateTime.UtcNow;

            var token = new JwtSecurityToken(
                    clientId,
                    audience,
                    new List<Claim>()
                    {
                        new Claim("jti", Guid.NewGuid().ToString()),
                        new Claim(JwtClaimTypes.Subject, clientId),
                        new Claim(JwtClaimTypes.IssuedAt, now.ToEpochTime().ToString(), ClaimValueTypes.Integer64)
                    },
                    now,
                    now.AddMinutes(1),
                    new SigningCredentials(
                        new X509SecurityKey(certificate),
                        SecurityAlgorithms.RsaSha256
                    )
                );

            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);             
        }
    }
}
