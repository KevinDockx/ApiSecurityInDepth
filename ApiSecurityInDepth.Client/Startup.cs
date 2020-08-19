using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using ApiSecurityInDepth.Client.Services;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;

namespace ApiSecurityInDepth.Client
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            services.AddControllersWithViews(); 

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "apisecurityclientcookiescheme";
                options.DefaultChallengeScheme = "oidc";
            })
                .AddCookie("apisecurityclientcookiescheme")
                //.AddOpenIdConnect("oidc", options =>
                //{
                //options.Authority = "https://localhost:44391";
                //options.RequireHttpsMetadata = false;
                //options.ResponseType = "code";
                //options.ClientId = "webclient";
                //options.ClientSecret = "secret";
                //options.Scope.Add("email");
                //options.Scope.Add("api1.fullaccess");
                //options.SaveTokens = true;

                //    #region ActorClaim
                //    options.Events = new OpenIdConnectEvents()
                //    {
                //        OnTokenValidated = ctx =>
                //        {
                //            // fyi: an IClaimsPrincipal can have multiple Identities (ClaimsIdentity),
                //            // and inherits all claims from the underlying identities.  

                //            // find the "act" claim
                //            // NOTE: don't use ctx.SecurityToken.Actor - that one will give you the 
                //            // value of the "actort" claim... sigh. 

                //            var actClaim = ctx.SecurityToken.Claims.FirstOrDefault(c => c.Type == "act");
                //            if (actClaim != null)
                //            {
                //                var actorClaims = new List<Claim>();

                //                var claimValueAsJObject = JObject.Parse(actClaim.Value);
                //                foreach (var jToken in claimValueAsJObject)
                //                {
                //                    actorClaims.Add(new Claim(jToken.Key, jToken.Value.ToString()));
                //                }

                //                // create the actor identity
                //                var actorIdentity = new ClaimsIdentity(actorClaims);

                //                // set as actor
                //                (ctx.Principal.Identity as ClaimsIdentity).Actor = actorIdentity;
                //            }

                //            return Task.CompletedTask;
                //        }
                //    };
                //    #endregion
                //});

              #region Code flow + PKCE with private key JWT for client authentication
             .AddOpenIdConnect("oidc", options =>
              {
                  options.Authority = "https://localhost:44391";
                  options.RequireHttpsMetadata = false;
                  options.ResponseType = "code";
                  options.ClientId = "webclientjwt";
                  options.Scope.Add("email");
                  options.Scope.Add("api1.fullaccess");
                  options.SaveTokens = true;

                  options.Events = new OpenIdConnectEvents()
                  {
                      OnTokenValidated = ctx =>
                      { 
                          var actClaim = ctx.SecurityToken.Claims.FirstOrDefault(c => c.Type == "act");
                          if (actClaim != null)
                          {
                              var actorClaims = new List<Claim>();

                              var claimValueAsJObject = JObject.Parse(actClaim.Value);
                              foreach (var jToken in claimValueAsJObject)
                              {
                                  actorClaims.Add(new Claim(jToken.Key, jToken.Value.ToString()));
                              }

                              // create the actor identity
                              var actorIdentity = new ClaimsIdentity(actorClaims);

                              // set as actor
                              (ctx.Principal.Identity as ClaimsIdentity).Actor = actorIdentity;
                          }
                          return Task.CompletedTask;
                      }
                  };
              });
            #endregion

            // register the generator for private key jwt tokens (used for client authentication)
            services.AddSingleton<ITokenGenerator, TokenGenerator>();

            #region Registration for Code flow + PKCE with private key JWT for client authentication
            // register the OpenIdPostConfigureOptions class.  In the OIDC configuration we need to know the token endpoint, 
            // and the best practice is to dynamically get that from the token endpoint.  To be able to do that, we need 
            // an HttpClient instance, and the best practice is using an HttpClientFactory for managing them.  
            // The issue is that we cannot inject such a factory in the ConfigureServices method, as it's not added on the 
            // container at that moment yet.  We could build an in-betweens serviceprovider in ConfigureServices and resolve
            // it like that: 
            //
            // var serviceProvider = services.BuildServiceProvider();
            // var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
            //
            // ... but that's a bad practice, as it means all singleton instances will be created twice.  
            // The solution is to use IPostConfigurationOptions and inject the factory in that class.  
            services.AddSingleton<IPostConfigureOptions<OpenIdConnectOptions>, OpenIdConnectOptionsPostConfigureOptions>();
            #endregion 

            services.AddHttpClient("IDPClient", client =>
            {
                client.BaseAddress = new Uri("https://localhost:44391/");
            });

            services.AddHttpClient("APIClient", client =>
            {
                client.BaseAddress = new Uri("https://localhost:44385/");
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });             
        }
    }
}
