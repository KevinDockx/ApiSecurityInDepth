using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ApiSecurityInDepth.API1.Controllers
{
    [Route("api/multihopclaims")]
    [ApiController]
    [Authorize]
    public class MultiHopClaimsController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public MultiHopClaimsController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        }

        public async Task<IActionResult> Get()
        {
            var idpClient = _httpClientFactory.CreateClient("IDPClient");

            var discoveryDocumentResponse = await idpClient.GetDiscoveryDocumentAsync();
            if (discoveryDocumentResponse.IsError)
            {
                throw new Exception(discoveryDocumentResponse.Error);
            }

            var customParams = new Dictionary<string, string>
            {
                { "subject_token_type",  "urn:ietf:params:oauth:token-type:access_token"},
                { "subject_token", await HttpContext.GetTokenAsync("access_token") },
                { "scope", "profile email api2.fullaccess" }
            }; 

            var tokenResponse = await idpClient.RequestTokenAsync(new TokenRequest()
            {
                 Address = discoveryDocumentResponse.TokenEndpoint,
                 GrantType = "urn:ietf:params:oauth:grant-type:token-exchange",
                 Parameters = customParams,
                 ClientId = "api1client", 
                 ClientSecret = "secret"
            });

            if (tokenResponse.IsError)
            {
                throw new Exception(tokenResponse.Error);
            }
        
            // call second API on behalf of the currently identified user
            // & return the claims via that API

            var multiHopClient = _httpClientFactory.CreateClient("MultiHopClient");
            multiHopClient.SetBearerToken(tokenResponse.AccessToken);

            var result = await multiHopClient.GetStringAsync("api/claims");
            var parsedResult = JArray.Parse(result.ToString());
            return new JsonResult(parsedResult);
        }
    }
}
