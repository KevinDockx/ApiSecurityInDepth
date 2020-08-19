using ApiSecurityInDepth.Client.Services;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace ApiSecurityInDepth.Client.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ITokenGenerator _tokenGenerator;

        public HomeController(IHttpClientFactory httpClientFactory, 
            ITokenGenerator tokenGenerator)
        {
            _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
            _tokenGenerator = tokenGenerator ?? throw new ArgumentNullException(nameof(tokenGenerator));
        }
        public async Task<IActionResult> Index()
        {
            await SetViewBag();          
            return View();
        }


        public async Task<IActionResult> CallApi()
        {
            var client = _httpClientFactory.CreateClient("APIClient");
            client.SetBearerToken(await HttpContext.GetTokenAsync("access_token"));

            var result = await client.GetStringAsync("api/claims");
            ViewBag.Json = JArray.Parse(result.ToString());

            return View("ApiResult"); 
        }

        public async Task<IActionResult> RevokeToken()
        {
            var client = _httpClientFactory.CreateClient("IDPClient");

            var discoveryDocumentResponse = await client.GetDiscoveryDocumentAsync();
            if (discoveryDocumentResponse.IsError)
            {
                throw new Exception(discoveryDocumentResponse.Error);
            }

            var tokenRevocationResponse = await client.RevokeTokenAsync(new TokenRevocationRequest
            {
                Address = discoveryDocumentResponse.RevocationEndpoint,
                ClientId = "webclient",
                ClientSecret = "secret",

                Token = await HttpContext.GetTokenAsync("access_token")
            }); 

            if (tokenRevocationResponse.IsError)
            {
                throw new Exception(tokenRevocationResponse.Error);
            }

            await SetViewBag();
            return View("Index");
        }


        public async Task<IActionResult> CallApiMultiHop()
        {
            var client = _httpClientFactory.CreateClient("APIClient");
            client.SetBearerToken(await HttpContext.GetTokenAsync("access_token"));

            var result = await client.GetStringAsync("api/multihopclaims");
            ViewBag.Json = JArray.Parse(result.ToString());

            return View("ApiResult"); 
        }

        public async Task<IActionResult> GetTokenWithPrivateKeyJWT()
        {
            var idpClient = _httpClientFactory.CreateClient("IDPClient");

            var discoveryDocumentResponse = await idpClient.GetDiscoveryDocumentAsync();
            if (discoveryDocumentResponse.IsError)
            {
                throw new Exception(discoveryDocumentResponse.Error);
            }
            
            var signedToken = _tokenGenerator.CreateSignedToken("api1jwtclient", discoveryDocumentResponse.TokenEndpoint);

            var tokenResponse = await idpClient.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = discoveryDocumentResponse.TokenEndpoint,
                ClientId = "api1jwtclient",
                Scope = "api1.fullaccess",

                ClientAssertion =
                {
                    Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                    Value = signedToken
                }
            });

            if (tokenResponse.IsError)
            {
                throw new Exception(tokenResponse.Error);
            } 

            // call API with the access token
            var client = _httpClientFactory.CreateClient("APIClient");
            client.SetBearerToken(tokenResponse.AccessToken);

            var result = await client.GetStringAsync("api/claims");
            ViewBag.Json = JArray.Parse(result.ToString());

            return View("ApiResult");
        }
 
        private async Task SetViewBag()
        {
            ViewBag.Message = "Claims";
            ViewBag.IdentityToken = await HttpContext.GetTokenAsync("id_token");
            ViewBag.AccessToken = await HttpContext.GetTokenAsync("access_token");
        }

        public IActionResult Logout()
        {
            return SignOut("apisecurityclientcookiescheme", "oidc");
        }
    }
}
