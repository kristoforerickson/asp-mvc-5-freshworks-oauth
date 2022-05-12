using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace asp_mvc_5_freshworks_oauth.Controllers
{
    public class OAuthController : Controller
    {
        public ActionResult Authorize()
        {
            if (Response.StatusCode != 200)
            {
                return View("AuthorizeError");
            }

            var authentication = HttpContext.GetOwinContext().Authentication;
            var ticket = authentication.AuthenticateAsync("ApplicationCookie").Result;
            var identity = ticket != null ? ticket.Identity : null;
            if (identity == null)
            {
                authentication.Challenge("ApplicationCookie");
                return new HttpUnauthorizedResult();
            }

            var scopes = (Request.QueryString.Get("scope") ?? "").Split(' ');


            identity = new ClaimsIdentity(identity.Claims, "Bearer", identity.NameClaimType, identity.RoleClaimType);
            foreach (var scope in scopes)
            {
                identity.AddClaim(new Claim("urn:oauth:scope", scope));
            }

            identity.AddClaim(new Claim("urn:oauth:email", identity.Name));
            identity.AddClaim(new Claim("urn:oauth:sub", identity.Name));
            identity.AddClaim(new Claim("email", identity.Name));
            identity.AddClaim(new Claim("sub", identity.Name));

            authentication.SignIn(identity);

            Dictionary<string, string> props = new Dictionary<string, string>();
            AuthenticationProperties properties = new AuthenticationProperties(props);
            AuthenticationTicket ticket2 = new AuthenticationTicket(identity, properties);
            DateTime currentUtc = DateTime.UtcNow;
            DateTime expireUtc = currentUtc.Add(TimeSpan.FromHours(24));
            ticket2.Properties.IssuedUtc = currentUtc;
            ticket2.Properties.ExpiresUtc = expireUtc;

            string redirect = $"{Request.QueryString.Get("redirect_uri")}?code={Uri.EscapeUriString(Startup.OAuthOptions.AccessTokenFormat.Protect(ticket2))}&state={Request.QueryString.Get("state")}&registration_id={Request.QueryString.Get("registration_id")}";

            return Redirect(redirect);
        }
    }
}