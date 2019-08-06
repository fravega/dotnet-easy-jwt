using EasyJWT.Helpers;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;

namespace EasyJWT
{
    public class JWTReader : IJWTReader
    {
        public IDictionary<string, object> Read(string token)
            => ParseClaimsToDictionary(new JwtSecurityTokenHandler().ReadJwtToken(token).Claims);

        public IDictionary<string, object> ReadAndValidate(string token, string issuer, string sharedKey, string publicRSAKeyPath)
        {
            var algorithm = new JwtSecurityTokenHandler().ReadJwtToken(token).SignatureAlgorithm;
            switch (algorithm)
            {
                case SecurityAlgorithms.HmacSha256:
                    return ReadAndValidateSymmetric(token, issuer, sharedKey);
                case SecurityAlgorithms.RsaSha512:
                    return ReadAndValidateAsymmetric(token, issuer, publicRSAKeyPath);
                default:
                    throw new ArgumentException($"Unknown signing algorithm {algorithm}");
            }
        }

        public IDictionary<string, object> ReadAndValidateAsymmetric(string token, string issuer, string publicRSAKeyPath)
            => ReadAndValidateJWT(token, issuer, BuildAndValidateAsymmetricPublicKey(publicRSAKeyPath));

        public IDictionary<string, object> ReadAndValidateSymmetric(string token, string issuer, string sharedKey)
            => ReadAndValidateJWT(token, issuer, BuildAndValidateSymmetricKey(sharedKey));

        private IDictionary<string, object> ReadAndValidateJWT(string token, string issuer, SecurityKey securityKey)
        {
            var claimsPrincipal = new JwtSecurityTokenHandler().ValidateToken(token, TokenValidationHelper.CreateParameters(issuer, securityKey), out SecurityToken validatedToken);
            return ParseClaimsToDictionary(claimsPrincipal.Claims);
        }

        private RsaSecurityKey BuildAndValidateAsymmetricPublicKey(string publicRSAKeyPath)
        {
            if (string.IsNullOrEmpty(publicRSAKeyPath))
                throw new ArgumentNullException(nameof(publicRSAKeyPath));

            if (!File.Exists(publicRSAKeyPath))
                throw new IOException($"File not found {publicRSAKeyPath}");

            return new RsaSecurityKey(RSAHelper.PublicKeyFromPemFile(publicRSAKeyPath));
        }

        private SymmetricSecurityKey BuildAndValidateSymmetricKey(string sharedKey)
        {
            if (string.IsNullOrEmpty(sharedKey))
                throw new ArgumentNullException(nameof(sharedKey));

            var symmetricSecurityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(sharedKey));

            if (symmetricSecurityKey.KeySize < 128)
                throw new ArgumentOutOfRangeException(nameof(sharedKey), message: $"Symmetric shared key must be greater than 128 bits. Given key has {symmetricSecurityKey.KeySize} bits.");

            return symmetricSecurityKey;
        }

        private IDictionary<string, object> ParseClaimsToDictionary(IEnumerable<Claim> claims)
            => claims
                .GroupBy(x => x.Type)
                .ToDictionary(x => x.Key, x => x.Count() <= 1 ? x.FirstOrDefault()?.Value : (object)x.Select(v => v.Value).ToList());
    }
}