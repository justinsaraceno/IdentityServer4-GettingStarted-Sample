using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Models;

namespace PizzaEnterprises.Configuration
{
    internal class Scopes
    {
        public static IEnumerable<Scope> Get()
        {
            return new List<Scope> {
            StandardScopes.OpenId,
            StandardScopes.Profile,
            StandardScopes.Email,
            StandardScopes.Roles,
            StandardScopes.OfflineAccess,
            new Scope {
                Name = "customAPI",
                DisplayName = "Custom API",
                Description = "Custom API scope",
                Type = ScopeType.Resource,
                Claims = new List<ScopeClaim> {
                    new ScopeClaim(JwtClaimTypes.Role)
                },
                ScopeSecrets =  new List<Secret> {
                    new Secret("scopeSecret".Sha256())
                }
            }
        };
        }
    }
}
