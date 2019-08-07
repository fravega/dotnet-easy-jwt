using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Easy.JWT.Helpers
{
    public static class RSAHelper
    {
        internal static RSACryptoServiceProvider PrivateKeyFromPemFile(String filePath)
        {
            using (TextReader privateKeyTextReader = new StringReader(File.ReadAllText(filePath)))
            {
                AsymmetricCipherKeyPair readKeyPair = (AsymmetricCipherKeyPair)new PemReader(privateKeyTextReader).ReadObject();

                RsaPrivateCrtKeyParameters privateKeyParams = ((RsaPrivateCrtKeyParameters)readKeyPair.Private);
                RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters
                {
                    Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned(),
                    P = privateKeyParams.P.ToByteArrayUnsigned(),
                    Q = privateKeyParams.Q.ToByteArrayUnsigned(),
                    DP = privateKeyParams.DP.ToByteArrayUnsigned(),
                    DQ = privateKeyParams.DQ.ToByteArrayUnsigned(),
                    InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned(),
                    D = privateKeyParams.Exponent.ToByteArrayUnsigned(),
                    Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned()
                };

                cryptoServiceProvider.ImportParameters(parms);

                return cryptoServiceProvider;
            }
        }

        public static RSACryptoServiceProvider PublicKeyFromPemFile(String filePath)
        {
            using (TextReader publicKeyTextReader = new StringReader(File.ReadAllText(filePath)))
            {
                RsaKeyParameters publicKeyParam = (RsaKeyParameters)new PemReader(publicKeyTextReader).ReadObject();

                RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters
                {
                    Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned(),
                    Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned()
                };

                cryptoServiceProvider.ImportParameters(parms);

                return cryptoServiceProvider;
            }
        }
    }
}