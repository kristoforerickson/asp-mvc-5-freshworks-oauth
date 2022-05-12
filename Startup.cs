using asp_mvc_5_freshworks_oauth.App_Start;
using asp_mvc_5_freshworks_oauth.Repositories;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Web.Http;

[assembly: OwinStartup(typeof(asp_mvc_5_freshworks_oauth.Startup))]

namespace asp_mvc_5_freshworks_oauth
{
    public class Startup
    {
        private readonly ConcurrentDictionary<string, string> _authenticationCodes = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }

       

        public void Configuration(IAppBuilder app)
        {
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);


            HttpConfiguration config = new HttpConfiguration();

            OAuthOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/oauth/token"),
                Provider = new OAuthAuthorizationServerProvider
                {
                    OnValidateClientRedirectUri = ValidateClientRedirectUri,
                    OnValidateClientAuthentication = ValidateClientAuthentication,
                    OnGrantResourceOwnerCredentials = GrantResourceOwnerCredentials,
                    OnGrantClientCredentials = GrantClientCredetails
                },
                AuthorizationCodeProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateAuthenticationCode,
                    OnReceive = ReceiveAuthenticationCode,
                },
                RefreshTokenProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateRefreshToken,
                    OnReceive = ReceiveRefreshToken,
                }
            };

            WebApiConfig.Register(config);
            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            app.UseWebApi(config);

            app.UseOAuthBearerTokens(OAuthOptions);


            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions() { });

            Database.SetInitializer(new MigrateDatabaseToLatestVersion<AuthContext, asp_mvc_5_freshworks_oauth.Migrations.Configuration>());
        }

        private Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            using (var repo = new AuthRepository())
            {
                var client = repo.FindClient(context.ClientId);
                if (client != null)
                {
                    context.Validated(client.AllowedOrigin);
                }
            }

            return Task.FromResult(0);
        }

        private Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId;
            string clientSecret;

            if (context.TryGetBasicCredentials(out clientId, out clientSecret) ||
                context.TryGetFormCredentials(out clientId, out clientSecret))
            {

                using (var repo = new AuthRepository())
                {
                    HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider();
                    byte[] byteValue = System.Text.Encoding.UTF8.GetBytes(clientSecret);
                    byte[] byteHash = hashAlgorithm.ComputeHash(byteValue);
                    var hashedSecret = Convert.ToBase64String(byteHash);

                    var client = repo.FindClient(clientId);
                    if (client != null && client.Secret == hashedSecret)
                    {
                        context.Validated(clientId);
                    }
                }
            }
            return Task.FromResult(0);
        }

        private void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
            context.SetToken(Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));
            _authenticationCodes[context.Token] = context.SerializeTicket();
        }

        private void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
            string value;
            if (_authenticationCodes.TryRemove(context.Token, out value))
            {
                context.DeserializeTicket(value);
            }

            Microsoft.Owin.Security.AuthenticationTicket ticket = Startup.OAuthOptions.AccessTokenFormat.Unprotect(context.Token);

            var userManager = context.OwinContext.GetUserManager<ApplicationUserManager>();

            var user = userManager.FindByEmail(ticket.Identity.Name);

            var identity = new ClaimsIdentity(new List<Claim>()
                {
                    new Claim(ClaimTypes.NameIdentifier, ticket.Identity.Name),
                    new Claim(ClaimTypes.Email, ticket.Identity.Name),
                    new Claim("urn:oauth:email", ticket.Identity.Name),
                    new Claim("urn:oauth:sub", ticket.Identity.Name),
                    new Claim("email", ticket.Identity.Name),
                    new Claim("sub", ticket.Identity.Name),
                }, DefaultAuthenticationTypes.ApplicationCookie);

            var authProps = new AuthenticationProperties();
            authProps.Dictionary.Add("client_id", user.ClientId);
            authProps.ExpiresUtc = DateTimeOffset.Now.AddMinutes(1);

            ticket = new AuthenticationTicket(identity, authProps);
            context.SetTicket(ticket);
        }

        private Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            List<Claim> claims = new List<Claim>();
            claims.AddRange(context.Scope.Select(x => new Claim("urn:oauth:scope", x)));


            claims.Add(new Claim("urn:oauth:email", context.UserName));
            claims.Add(new Claim("urn:oauth:sub", context.UserName));
            claims.Add(new Claim("email", context.UserName));
            claims.Add(new Claim("sub", context.UserName));

            var identity = new ClaimsIdentity(new GenericIdentity(context.UserName, OAuthDefaults.AuthenticationType), claims);

            context.Validated(identity);

            return Task.FromResult(0);
        }

        private Task GrantClientCredetails(OAuthGrantClientCredentialsContext context)
        {
            var identity = new ClaimsIdentity(new GenericIdentity(
                context.ClientId, OAuthDefaults.AuthenticationType),
                context.Scope.Select(x => new Claim("urn:oauth:scope", x))
                );

            context.Validated(identity);

            return Task.FromResult(0);
        }

        private void CreateRefreshToken(AuthenticationTokenCreateContext context)
        {
            context.SetToken(context.SerializeTicket());
        }

        private void ReceiveRefreshToken(AuthenticationTokenReceiveContext context)
        {
            context.DeserializeTicket(context.Token);
        }
    }
}
