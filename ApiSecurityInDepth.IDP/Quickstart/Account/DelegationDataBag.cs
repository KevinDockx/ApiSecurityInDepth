using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ApiSecurityInDepth.IDP.Quickstart.Account
{
    public class DelegationDataBag
    {
            public string Subject { get; set; }
            public string UserName { get; set; }
            public string ReturnUrl { get; set; }
            public bool RememberLogin { get; set; }        
    }
}
