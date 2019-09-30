using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiSecurityInDepth.API1.Controllers
{
    [Route("api/claims")]
    [ApiController]
    [Authorize]
    public class ClaimsController : ControllerBase
    {   
        [HttpGet]
        public IActionResult Get()
        {
            var claims = from c in User.Claims
                         select new
                         {
                             type = c.Type,
                             value = c.Value
                         };

            return new JsonResult(claims);
        } 
    }
}
