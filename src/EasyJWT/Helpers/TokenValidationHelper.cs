using Microsoft.IdentityModel.Tokens;

namespace EasyJWT.Helpers
{
    public static class TokenValidationHelper
    {
        /// <summary>
        /// Creates a TokenValidationParameters that supports multiple key validation.
        /// </summary>
        public static TokenValidationParameters CreateParameters(params SecurityKey[] securityKeys)
            => new TokenValidationParameters
            {
                ValidateLifetime = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = securityKeys
            };

        /// <summary>
        /// Creates a TokenValidationParameters that supports multiple key validation and validates the issuer claim.
        /// </summary>
        public static TokenValidationParameters CreateParameters(string issuer, params SecurityKey[] securityKeys)
            => new TokenValidationParameters
            {
                ValidateLifetime = true,
                ValidateAudience = false,
                ValidateIssuer = true,
                ValidIssuer = issuer,
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = securityKeys
            };
    }
}