using System;
using System.Collections.Generic;

namespace Easy.JWT
{
    /// <summary>
    /// Contains methods tu build JWT tokens using different signing algorithms.
    /// </summary>
    public interface IJWTWriter
    {
        /// <summary>
        /// Builds a JWT token signing it with an asymmetric algorithm (RsaSha512) using a private key.
        /// </summary>
        /// <param name="issuer">Issuer that signes the token.</param>
        /// <param name="audience">Target to use the token.</param>
        /// <param name="expiresOn">The expiration time for this token (in UTC).</param>
        /// <param name="privateRsaKeyPath">Path of the private RSA key.</param>
        /// <param name="claims">Aditional claims to add to token payload.</param>
        /// <returns>An asymmetrically signed JWT token</returns>
        string WriteAsymmetric(string issuer, string audience, DateTime expiresOn, string privateRsaKeyPath, Dictionary<string, object> claims);

        /// <summary>
        /// Builds a JWT token signing it with an symmetric algorithm (HmacSha256) using a private key.
        /// </summary>
        /// <param name="issuer">Issuer that signes the token.</param>
        /// <param name="audience">Target to use the token.</param>
        /// <param name="expiresOn">The expiration time for this token (in UTC).</param>
        /// <param name="sharedKey">Shared key used to sign/validate the token. It must be greater than 128 bits.</param>
        /// <param name="claims">Aditional claims to add to token payload.</param>
        /// <returns>A symmetrically signed JWT token</returns>
        string WriteSymmetric(string issuer, string audience, DateTime expiresOn, string sharedKey, Dictionary<string, object> claims);
    }
}