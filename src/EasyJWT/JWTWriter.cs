using EasyJWT.Helpers;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;

namespace EasyJWT
{
    public class JWTWriter : IJWTWriter
    {
        public string WriteAsymmetric(string issuer, string audience, DateTime expiresOn, string privateRSAKeyPath, Dictionary<string, object> claims)
        {
            if (string.IsNullOrEmpty(privateRSAKeyPath))
                throw new ArgumentNullException(nameof(privateRSAKeyPath));
                
            if (!File.Exists(privateRSAKeyPath))
                throw new IOException($"File not found {privateRSAKeyPath}");

            RSA privateRsa = RSAHelper.PrivateKeyFromPemFile(privateRSAKeyPath);

            return WriteJWT(issuer, audience, expiresOn, new SigningCredentials(new RsaSecurityKey(privateRsa), SecurityAlgorithms.RsaSha512), claims);
        }

        public string WriteSymmetric(string issuer, string audience, DateTime expiresOn, string sharedKey, Dictionary<string, object> claims)
        {
            if (string.IsNullOrEmpty(sharedKey))
                throw new ArgumentNullException(nameof(sharedKey));

            var symmetricSecurityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(sharedKey));

            if (symmetricSecurityKey.KeySize < 128)
                throw new ArgumentOutOfRangeException(nameof(sharedKey), message: $"Symmetric shared key must be greater than 128 bits. Given key has {symmetricSecurityKey.KeySize} bits.");

            return WriteJWT(issuer, audience, expiresOn, new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256), claims);
        }

        private string WriteJWT(string issuer, string audience, DateTime expiresOn, SigningCredentials signingCredentials, Dictionary<string, object> claims)
        {
            if (string.IsNullOrEmpty(issuer))
                throw new ArgumentNullException(nameof(issuer));

            if (string.IsNullOrEmpty(audience))
                throw new ArgumentNullException(nameof(audience));

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: GetClaimListFromDictionary(claims),
                expires: expiresOn,
                signingCredentials: signingCredentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private IEnumerable<Claim> GetClaimListFromDictionary(Dictionary<string, object> claims)
        {
            foreach (var claim in claims)
            {
                if (claim.Value is IEnumerable valueList && !typeof(string).IsAssignableFrom(claim.Value?.GetType()))
                    foreach(var value in valueList)
                        yield return CreateClaim(claim.Key, value);
                else
                    yield return CreateClaim(claim.Key, claim.Value);
            }
        }

        private Claim CreateClaim(string key, object value)
        {
            var type = ClaimValueTypes.String;
            if (value is bool)
                type = ClaimValueTypes.Boolean;
            else if (value is int)
                type = ClaimValueTypes.Integer;
            else if (value is DateTime)
                type = ClaimValueTypes.DateTime;

            return new Claim(key, value?.ToString(), type);
        }
    }
}