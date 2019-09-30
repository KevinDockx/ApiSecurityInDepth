// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace ApiSecurityInDepth.IDP
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email()
            };
        }

        public static IEnumerable<ApiResource> GetApis()
        {
            return new ApiResource[]
            {
                #region JWT
             //   new ApiResource("api1", "API1", new[] { "profile", "email" }),
                #endregion

                #region Reference token
                new ApiResource("api1", "API1", new[] { "profile", "email" })
                {
                    ApiSecrets = { new Secret("apisecret".Sha256()) }
                },
                #endregion

                new ApiResource("api2", "API2", new[] { "profile", "email" })
            };
        }

        public static IEnumerable<Client> GetClients()
        {
            return new[]
            {
                 new Client
                {
                    ClientId = "api1client",
                    ClientName = "API1 Client",

                    AllowedGrantTypes = new[] { "urn:ietf:params:oauth:grant-type:token-exchange" },
                    RequireConsent = false,                 
                    ClientSecrets = { new Secret("secret".Sha256()) },
                
                    AllowedScopes = {
                         IdentityServerConstants.StandardScopes.OpenId,
                         IdentityServerConstants.StandardScopes.Profile, 
                         IdentityServerConstants.StandardScopes.Email,
                         "api2" }
                },                  
                new Client
                {
                    ClientId = "webclient",
                    ClientName = "API Security in Depth Web Client",

                    RequireConsent = false,
                    AllowedGrantTypes = GrantTypes.Hybrid,
                    ClientSecrets = { new Secret("secret".Sha256()) },
                    AlwaysIncludeUserClaimsInIdToken = true,
                    RedirectUris = { "https://localhost:44375/signin-oidc" },
                    FrontChannelLogoutUri = "https://localhost:44375/signout-oidc",
                    PostLogoutRedirectUris = { "https://localhost:44375/signout-callback-oidc" },

                    AccessTokenType = AccessTokenType.Reference,

                    AllowOfflineAccess = true,
                    AllowedScopes = { "openid", "profile", "email", "api1" }
                },
               new Client
               {
                    ClientId = "api1jwtclient",
                    ClientSecrets =
                    {
                        new Secret
                        {
                            Type = IdentityServerConstants.SecretTypes.X509CertificateBase64,
                            Value = "MIIDATCCAe2gAwIBAgIQoHUYAquk9rBJcq8W+F0FAzAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB0RldlJvb3QwHhcNMTAwMTIwMjMwMDAwWhcNMjAwMTIwMjMwMDAwWjARMQ8wDQYDVQQDEwZDbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSaY4x1eXqjHF1iXQcF3pbFrIbmNw19w/IdOQxbavmuPbhY7jX0IORu/GQiHjmhqWt8F4G7KGLhXLC1j7rXdDmxXRyVJBZBTEaSYukuX7zGeUXscdpgODLQVay/0hUGz54aDZPAhtBHaYbog+yH10sCXgV1Mxtzx3dGelA6pPwiAmXwFxjJ1HGsS/hdbt+vgXhdlzud3ZSfyI/TJAnFeKxsmbJUyqMfoBl1zFKG4MOvgHhBjekp+r8gYNGknMYu9JDFr1ue0wylaw9UwG8ZXAkYmYbn2wN/CpJl3gJgX42/9g87uLvtVAmz5L+rZQTlS1ibv54ScR2lcRpGQiQav/LAgMBAAGjXDBaMBMGA1UdJQQMMAoGCCsGAQUFBwMCMEMGA1UdAQQ8MDqAENIWANpX5DZ3bX3WvoDfy0GhFDASMRAwDgYDVQQDEwdEZXZSb290ghAsWTt7E82DjU1E1p427Qj2MAkGBSsOAwIdBQADggEBADLje0qbqGVPaZHINLn+WSM2czZk0b5NG80btp7arjgDYoWBIe2TSOkkApTRhLPfmZTsaiI3Ro/64q+Dk3z3Kt7w+grHqu5nYhsn7xQFAQUf3y2KcJnRdIEk0jrLM4vgIzYdXsoC6YO+9QnlkNqcN36Y8IpSVSTda6gRKvGXiAhu42e2Qey/WNMFOL+YzMXGt/nDHL/qRKsuXBOarIb++43DV3YnxGTx22llhOnPpuZ9/gnNY7KLjODaiEciKhaKqt/b57mTEz4jTF4kIg6BP03MUfDXeVlM1Qf1jB43G2QQ19n5lUiqTpmQkcfLfyci2uBZ8BkOhXr3Vk9HIk/xBXQ="
                        }
                    },

                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes = { "api1" }
                }
            };
        }
    }
}