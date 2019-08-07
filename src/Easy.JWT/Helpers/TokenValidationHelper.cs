using Microsoft.IdentityModel.Tokens;

namespace Easy.JWT.Helpers
{
    public static class TokenValidationHelper
    {
        /// <summary>
        /// Creates a TokenValidationParameters that supports multiple key validation and validates the issuer claim.
        /// </summary>
        public static TokenValidationParameters CreateParameters(this ValidationParameters @this, params SecurityKey[] securityKeys)
            => new TokenValidationParameters
            {
                ValidateLifetime = @this.ValidateLifetime,
                ValidateAudience = !string.IsNullOrEmpty(@this.ValidAudience),
                ValidAudience = @this.ValidAudience,
                ValidateIssuer = !string.IsNullOrEmpty(@this.ValidIssuer),
                ValidIssuer = @this.ValidIssuer,
                ValidateIssuerSigningKey = !string.IsNullOrEmpty(@this.ValidIssuer),
                RequireSignedTokens = true,
                IssuerSigningKeys = securityKeys
            };
    }
}