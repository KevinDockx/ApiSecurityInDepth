using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ApiSecurityInDepth.IDP.Quickstart.Account
{
    public class LoginDelegationInputViewModel
    {
        public List<LocalUser> PotentialUsers { get; set; }
        = new List<LocalUser>();

        public LocalUser CurrentUser { get; set; }
    }
}
