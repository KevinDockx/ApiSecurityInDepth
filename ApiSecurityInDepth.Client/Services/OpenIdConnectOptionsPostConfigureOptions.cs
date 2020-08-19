using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace ApiSecurityInDepth.Client.Services
{
    public class OpenIdConnectOptionsPostConfigureOptions : IPostConfigureOptions<OpenIdConnectOptions>
    {
        private readonly IHttpClientFactory _clientFactory;
        private readonly ITokenGenerator _tokenGenerator;

        public OpenIdConnectOptionsPostConfigureOptions(
            IHttpClientFactory clientFactory,
            ITokenGenerator tokenGenerator,
            ILogger<OpenIdConnectOptionsPostConfigureOptions> logger)
        {
            _clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
            _tokenGenerator = tokenGenerator ?? throw new ArgumentNullException(nameof(tokenGenerator));
        }

        public void PostConfigure(string name, OpenIdConnectOptions options)
        {
            var idpClient = _clientFactory.CreateClient("IDPClient");

            // Read out the discovery document.  This isn't required, but it avoids having
            // to hard-code the token endpoint URL.  
            var discoveryDocument = idpClient.GetDiscoveryDocumentAsync().Result;
            if (discoveryDocument.IsError)
            {
                throw new Exception(discoveryDocument.Error);
            }             

            options.Events = new OpenIdConnectEvents()
            {
                // other configuration
                OnAuthorizationCodeReceived = context =>
                {
                    var token = _tokenGenerator.CreateSignedToken(
                        "webclientjwt",
                        discoveryDocument.TokenEndpoint);

                    context.TokenEndpointRequest.ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
                    context.TokenEndpointRequest.ClientAssertion = token;

                    return Task.CompletedTask;
                }                 
            };
        }
    }
}

