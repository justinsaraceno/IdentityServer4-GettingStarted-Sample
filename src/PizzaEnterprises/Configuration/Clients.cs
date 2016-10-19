﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Models;

namespace PizzaEnterprises.Configuration
{
    internal class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new List<Client> {
            new Client {
                ClientId = "oauthClient",
                ClientName = "Example Client Credentials Client Application",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = new List<Secret> {
                    new Secret("superSecretPassword".Sha256())},
                AllowedScopes = new List<string> {"customAPI"}
            },
            new Client {
                ClientId = "openIdConnectClient",
                ClientName = "Example Implicit Client Application",
                AllowedGrantTypes = GrantTypes.Implicit,
                AllowedScopes = new List<string>
                {
                    StandardScopes.OpenId.Name,
                    StandardScopes.Profile.Name,
                    StandardScopes.Email.Name,
                    StandardScopes.Roles.Name,
                    "customAPI"
                },
                RedirectUris = new List<string> {"https://localhost:44393/signin-oidc"},
                PostLogoutRedirectUris = new List<string> { "https://localhost:44393" }
            }
        };
        }
    }
}
