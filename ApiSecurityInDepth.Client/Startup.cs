using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
                .AddOpenIdConnect("oidc", options =>
                {
                options.Authority = "https://localhost:44391";
                options.RequireHttpsMetadata = false;
                options.ResponseType = "code id_token";
                options.ClientId = "webclient";
                options.ClientSecret = "secret";
                options.Scope.Add("email");
                options.Scope.Add("api1");
                options.SaveTokens = true;

                    #region ActorClaim
                    options.Events = new OpenIdConnectEvents()
                    {
                        OnTokenValidated = ctx =>
                        {
                            // fyi: an IClaimsPrincipal can have multiple Identities (ClaimsIdentity),
                            // and inherits all claims from the underlying identities.  

                            // find the "act" claim
                            // NOTE: don't use ctx.SecurityToken.Actor - that one will give you the 
                            // value of the "actort" claim... sigh. 

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
                    #endregion
                });

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
