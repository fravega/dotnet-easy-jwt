using EasyJWT.Helpers;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace EasyJWT
{
    public class JWTReader : JWT, IJWTReader
    {
        public JWTReader() => IdentityModelEventSource.ShowPII = true;
        public IDictionary<string, object> Read(string token)
            => ParseClaimsToDictionary(new JwtSecurityTokenHandler().ReadJwtToken(token).Claims);

        public IDictionary<string, object> ReadAndValidate(string token, string issuer, string sharedKey, string publicRSAKeyPath) 
            => ReadAndValidate(token, ValidationParameters.Default(issuer), sharedKey, publicRSAKeyPath);

        public IDictionary<string, object> ReadAndValidate(string token, ValidationParameters validationParameters, string sharedKey, string publicRSAKeyPath)
        {
            var algorithm = new JwtSecurityTokenHandler().ReadJwtToken(token).SignatureAlgorithm;
            switch (algorithm)
            {
                case SecurityAlgorithms.HmacSha256:
                    return ReadAndValidateSymmetric(token, validationParameters, sharedKey);
                case SecurityAlgorithms.RsaSha512:
                    return ReadAndValidateAsymmetric(token, validationParameters, publicRSAKeyPath);
                default:
                    throw new ArgumentException($"Unknown signing algorithm {algorithm}");
            }
        }

        public IDictionary<string, object> ReadAndValidateAsymmetric(string token, string issuer, string publicRSAKeyPath)
            => ReadAndValidateAsymmetric(token, ValidationParameters.Default(issuer), publicRSAKeyPath);

        public IDictionary<string, object> ReadAndValidateAsymmetric(string token, ValidationParameters validationParameters, string publicRSAKeyPath)
            => ReadAndValidateJWT(token, validationParameters, BuildRSAPublicKey(publicRSAKeyPath));

        public IDictionary<string, object> ReadAndValidateSymmetric(string token, string issuer, string sharedKey)
            => ReadAndValidateSymmetric(token, ValidationParameters.Default(issuer), sharedKey);

        public IDictionary<string, object> ReadAndValidateSymmetric(string token, ValidationParameters validationParameters, string sharedKey)
            => ReadAndValidateJWT(token, validationParameters, BuildSymmetricKey(sharedKey));

        private IDictionary<string, object> ReadAndValidateJWT(string token, ValidationParameters validationParameters, SecurityKey securityKey)
        {
            var claimsPrincipal = new JwtSecurityTokenHandler().ValidateToken(token, validationParameters.CreateParameters(securityKey), out SecurityToken validatedToken);
            return ParseClaimsToDictionary(claimsPrincipal.Claims);
        }

        private IDictionary<string, object> ParseClaimsToDictionary(IEnumerable<Claim> claims)
            => claims
                .GroupBy(x => x.Type)
                .ToDictionary(x => x.Key, x => x.Count() <= 1 ? ParseClaim(x.FirstOrDefault()) : (object)x.Select(v => ParseClaim(v)).ToArray());
        
        private object ParseClaim(Claim claim)
        {
            if (claim == null)
                return null;

            switch (claim.ValueType)
            {
                case ClaimValueTypes.Boolean:
                    if (bool.TryParse(claim.Value, out bool boolVal)) return boolVal;
                    break;
                case ClaimValueTypes.Integer:
                case ClaimValueTypes.Integer32:
                    if (int.TryParse(claim.Value, out int intVal)) return intVal;
                    break;
                case ClaimValueTypes.Integer64:
                    if (Int64.TryParse(claim.Value, out long longVal)) return longVal;
                    break;
                case ClaimValueTypes.Double:
                    if (decimal.TryParse(claim.Value, out decimal decimalVal)) return decimalVal;
                    break;
                case ClaimValueTypes.DateTime:
                    if (DateTime.TryParse(claim.Value, out DateTime dt)) return dt;
                    break;
            }
            return claim.Value;
        }
    }
}