using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Test;
using IdentityServerHost.Quickstart.UI;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace ApiSecurityInDepth.IDP.Services
{
    public class DelegatedProfileService : IProfileService
    {
        public DelegatedProfileService()
        {
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            // get the current logged-in subject          
            var subjectId = context.Subject.GetSubjectId();
            var claimsForUser = TestUsers.Users.First(u => u.SubjectId == subjectId).Claims;

            // set issued claims for the logged-in subject
            context.IssuedClaims = claimsForUser
                .Where(c => context.RequestedClaimTypes.Contains(c.Type))
                .Select(c => new Claim(c.Type, c.Value))
                .ToList();

            // get the actor's subject
            var actorClaimValue = context.Subject.Claims.FirstOrDefault(c => c.Type == "act")?.Value;
                       
            if (actorClaimValue != null)
            {
                dynamic convertedActorClaimValue = JToken.Parse(actorClaimValue);
                var actorSubject = ((JValue)convertedActorClaimValue.sub).Value.ToString();
                var actor = TestUsers.Users.First(u => u.SubjectId == actorSubject);
                if (actor != null)
                {
                    // set subject & issued claims for the actor
                    var actBuilder = new StringBuilder();

                    actBuilder.Append(@"{""sub"":""");
                    actBuilder.Append(actorSubject);
                    actBuilder.Append(@""",");

                    foreach (var claim in actor.Claims
                                .Where(c => context.RequestedClaimTypes.Contains(c.Type))
                                .Select(c => new Claim(c.Type, c.Value))
                                .ToList())
                    {
                        actBuilder.Append(@"""");
                        actBuilder.Append(claim.Type);
                        actBuilder.Append(@""":""");
                        actBuilder.Append(claim.Value);
                        actBuilder.Append(@""",");
                    }
                    actBuilder.Remove(actBuilder.Length-1, 1);
                    actBuilder.Append("}");

                    // add the actor as "act" claim
                    context.IssuedClaims.Add(new Claim("act", actBuilder.ToString(),
                        IdentityServer4.IdentityServerConstants.ClaimValueTypes.Json));
                }
            }
        }

        public async Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
        }
    }
}
