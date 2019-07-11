using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace secure_api
{
    /// <summary>Represents a certificate in PFX format.</summary>
    public class PfxCertificate
    {
        /// <summary>Gets or sets the PFX contents of the certificate.</summary>
        public byte[] PfxContents { get; set; }

        /// <summary>Gets or sets the thumbprint of the certificate.</summary>
        public string Thumbprint { get; set; }

        /// <summary>Gets or sets the version of the certificate.</summary>
        public string Version { get; set; }

        /// <summary>Converts the PFX certificate into PEM format.</summary>
        public PemCertificate ToPemCertificate()
        {
            X509Certificate2 x509Certificate2 = ToX509Certificate2();
            X509Chain x509Chain = new X509Chain();
            x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            x509Chain.Build(x509Certificate2);
            string[] array = x509Chain.ChainElements.Cast<X509ChainElement>().Select(
                x =>
                    "-----BEGIN CERTIFICATE-----\n" +
                    Convert.ToBase64String(x.Certificate.Export(X509ContentType.Cert)).SplitLength(64, "\n") +
                    "-----END CERTIFICATE-----\n").ToArray();
            AsymmetricCipherKeyPair rsaKeyPair = DotNetUtilities.GetRsaKeyPair((RSA) x509Certificate2.PrivateKey);
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (StreamWriter streamWriter = new StreamWriter(memoryStream))
                    new PemWriter(streamWriter).WriteObject(rsaKeyPair.Private);
                memoryStream.Flush();
                return new PemCertificate()
                {
                    CertificateChain = array.ToArray(),
                    PrivateKey = Encoding.ASCII.GetString(memoryStream.ToArray()).Replace("\r\n", "\n"),
                    Thumbprint = Thumbprint
                };
            }
        }

        /// <summary>
        /// Converts the certificate to <see cref="T:System.Security.Cryptography.X509Certificates.X509Certificate2" /> format, with private key.
        /// </summary>
        public X509Certificate2 ToX509Certificate2()
        {
            return new X509Certificate2(PfxContents, string.Empty, X509KeyStorageFlags.Exportable);
        }
    }

    internal static class SecretBrokerStringExtensions
    {
        /// <summary>
        /// Splits a string based on length, with the given separator.
        /// </summary>
        public static string SplitLength(this string value, int length, string separator = "\n")
        {
            StringBuilder stringBuilder = new StringBuilder();
            int length1;
            for (int startIndex = 0; startIndex < value.Length; startIndex += length1)
            {
                length1 = Math.Min(64, value.Length - startIndex);
                stringBuilder.AppendFormat("{0}{1}", value.Substring(startIndex, length1), separator);
            }

            return stringBuilder.ToString();
        }
    }
}