// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using ApiSecurityInDepth.IDP.Services;
using IdentityServer4;
using IdentityServer4.Validation;
using IdentityServerHost.Quickstart.UI;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ApiSecurityInDepth.IDP
{
    public class Startup
    {
        public IWebHostEnvironment Environment { get; }
        public IConfiguration Configuration { get; }

        public Startup(IWebHostEnvironment environment, IConfiguration configuration)
        {
            Environment = environment;
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                // see https://identityserver4.readthedocs.io/en/latest/topics/resources.html
                options.EmitStaticAudienceClaim = true;
            })
                .AddTestUsers(TestUsers.Users);

            // in-memory, code config
            builder.AddInMemoryIdentityResources(Config.IdentityResources);
            builder.AddInMemoryApiScopes(Config.ApiScopes);
            builder.AddInMemoryApiResources(Config.ApiResources);
            builder.AddInMemoryClients(Config.Clients);

            // add private key JWT secret validator & parser
            //builder.AddSecretParser<JwtBearerClientAssertionSecretParser>();
            //builder.AddSecretValidator<PrivateKeyJwtSecretValidator>();

             
            builder.AddSecretParser<JwtBearerClientAssertionSecretParser>();
            // this validator used to work in IdSrv4 3.x, but fails in 4.x due to an unresolvable
            // dependency on an IReplayCache.  Possible solutions: register an instance 
            // of an IReplayCache implementing class, or write a custom validator.  
            //
            // As an example: going for the custom validator approach.
            // builder.AddSecretValidator<PrivateKeyJwtSecretValidator>();
            builder.AddSecretValidator<CustomPrivateKeyJwtSecretValidator>();

            // add extension grant
            builder.AddExtensionGrantValidator<TokenExchangeExtensionGrantValidator>();

            // add custom profile service for delegation
            builder.AddProfileService<DelegatedProfileService>();

            // not recommended for production - you need to store your key material somewhere secure
            builder.AddDeveloperSigningCredential();           
        }

        public void Configure(IApplicationBuilder app)
        {
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();

            app.UseRouting();
            app.UseIdentityServer();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}