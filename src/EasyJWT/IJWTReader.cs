using System.Collections.Generic;

namespace EasyJWT
{
    /// <summary>
    /// Contains methods to read and validate JWT tokens using different types of signing keys.
    /// </summary>
    public interface IJWTReader
    {

        /// <summary>
        /// Reads a JWT token.
        /// </summary>
        /// <param name="token">The JWT token to read.</param>
        /// <returns>A map containing JWT payload claims deserialized.</returns>
        IDictionary<string, object> Read(string token);

        /// <summary>
        /// Reads a JWT token and validates it using an asymmetric or symmetric key, depending on JWT header algorithm.
        /// </summary>
        /// <param name="token">The JWT token to read.</param>
        /// <param name="issuer">Issuer that signs the token.</param>
        /// <param name="sharedKey">Shared key used to sign/validate the token. It must be greater than 128 bits.</param>
        /// <param name="publicRSAKeyPath">Path of the public RSA key.</param>
        /// <returns>A map containing JWT payload claims deserialized.</returns>
        IDictionary<string, object> ReadAndValidate(string token, string issuer, string sharedKey, string publicRSAKeyPath);

        /// <summary>
        /// Reads a JWT token and validates it using an symmetric shared key.
        /// </summary>
        /// <param name="token">The JWT token to read.</param>
        /// <param name="issuer">Issuer that signs the token.</param>
        /// <param name="sharedKey">Shared key used to sign/validate the token. It must be greater than 128 bits.</param>
        /// <returns>A map containing JWT payload claims deserialized.</returns>
        IDictionary<string, object> ReadAndValidateSymmetric(string token, string issuer, string sharedKey);

        /// <summary>
        /// Reads a JWT token and validates it using an asymmetric public key.
        /// </summary>
        /// <param name="token">The JWT token to read.</param>
        /// <param name="issuer">Issuer that signes the token.</param>
        /// <param name="publicRSAKeyPath">Path of the public RSA key.</param>
        /// <returns>A map containing JWT payload claims deserialized.</returns>
        IDictionary<string, object> ReadAndValidateAsymmetric(string token, string issuer, string publicRSAKeyPath);
    }
}