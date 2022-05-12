namespace asp_mvc_5_freshworks_oauth.Migrations
{
    using asp_mvc_5_freshworks_oauth.Entities;
    using System;
    using System.Collections.Generic;
    using System.Data.Entity;
    using System.Data.Entity.Migrations;
    using System.Linq;
    using System.Security.Cryptography;

    internal sealed class Configuration : DbMigrationsConfiguration<asp_mvc_5_freshworks_oauth.AuthContext>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = false;
        }

        protected override void Seed(asp_mvc_5_freshworks_oauth.AuthContext context)
        {
            if (context.Clients.Count() > 0)
            {
                return;
            }

            context.Clients.AddRange(BuildClientsList());
            context.SaveChanges();
        }

        private static List<Client> BuildClientsList()
        {
            HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider();
            byte[] byteValue = System.Text.Encoding.UTF8.GetBytes("abc@123");
            byte[] byteHash = hashAlgorithm.ComputeHash(byteValue);
            var hashedSecret = Convert.ToBase64String(byteHash);

            List<Client> ClientsList = new List<Client>
            {
                new Client
                { 
                    Id = "testmetest",
                    Secret= hashedSecret,
                    Name="FreshWorks Test SSO App",
                    Active = true,
                    RefreshTokenLifeTime = 7200,
                    AllowedOrigin = "https://getaxey.myfreshworks.com/sp/OAUTH/444494898955480487/callback"
                }
            };

            return ClientsList;
        }
    }
}
