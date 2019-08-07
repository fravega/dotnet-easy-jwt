using EasyJWT.Helpers;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IO;

namespace EasyJWT
{
    public abstract class JWT
    {
        protected SymmetricSecurityKey BuildSymmetricKey(string sharedKey)
        {
            if (string.IsNullOrEmpty(sharedKey))
                throw new ArgumentNullException(nameof(sharedKey));

            var symmetricSecurityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(sharedKey));

            if (symmetricSecurityKey.KeySize < 128)
                throw new ArgumentOutOfRangeException(nameof(sharedKey), message: $"Symmetric shared key must be greater than 128 bits. Given key has {symmetricSecurityKey.KeySize} bits.");

            return symmetricSecurityKey;
        }

        protected RsaSecurityKey BuildRSAPublicKey(string publicRSAKeyPath)
        {
            ValidateRSAKeyFile(publicRSAKeyPath);
            return new RsaSecurityKey(RSAHelper.PublicKeyFromPemFile(publicRSAKeyPath));
        }

        protected RsaSecurityKey BuildRSAPrivateKey(string privateRSAKeyPath)
        {
            ValidateRSAKeyFile(privateRSAKeyPath);
            return new RsaSecurityKey(RSAHelper.PrivateKeyFromPemFile(privateRSAKeyPath));
        }

        private void ValidateRSAKeyFile(string path)
        {
            if (string.IsNullOrEmpty(path))
                throw new ArgumentNullException(nameof(path));
                
            if (!File.Exists(path))
                throw new IOException($"RSA key not found in path {path}");
        }
    }
}