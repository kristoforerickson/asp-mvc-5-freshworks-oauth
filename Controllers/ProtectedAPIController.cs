using asp_mvc_5_freshworks_oauth.Repositories;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace asp_mvc_5_freshworks_oauth.Controllers
{
    [RoutePrefix("api/protected")]
    public class ProtectedAPIController : ApiController
    {
        private AuthRepository _repo = null;

        public ProtectedAPIController()
        {
            _repo = new AuthRepository();
        }


        [Route("")]
        public IHttpActionResult Get()
        {

            System.Net.Http.Headers.AuthenticationHeaderValue authorizationHeader = Request.Headers.Authorization;
            Microsoft.Owin.Security.AuthenticationTicket ticket = Startup.OAuthOptions.AccessTokenFormat.Unprotect(authorizationHeader.Parameter);

            dynamic result = new {};
            var claim = ticket.Identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name);    
            
            if (claim == null)
            {
                claim = ticket.Identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
            }

            if (!String.IsNullOrEmpty(claim?.Value))
            {
                var user = _repo.FindUser(claim?.Value);
                result = new { id = user.Id, email = user.UserName, sub = user.UserName };
            }

            return Json(result);
        }
    }
}