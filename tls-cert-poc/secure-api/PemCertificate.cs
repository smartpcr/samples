namespace secure_api
{
    /// <summary>
    /// Represents a certificate in PEM format (certificate chain + private key).
    /// </summary>
    public class PemCertificate
    {
        /// <summary>
        /// Gets or sets the chain of certificates, each in PEM format.
        /// </summary>
        public string[] CertificateChain { get; set; }

        /// <summary>
        /// Gets or sets the certificate's private key, in PEM format.
        /// </summary>
        public string PrivateKey { get; set; }

        /// <summary>Gets or sets the thumbprint of the certificate</summary>
        public string Thumbprint { get; set; }

        /// <summary>
        /// Gets the entire certificate as a single PEM block, which includes the certificate chain
        /// and the private key.
        /// </summary>
        public string ToPem()
        {
            return this.ToPemCertificateChain() + this.PrivateKey;
        }

        /// <summary>Gets the certificate chain in PEM format.</summary>
        public string ToPemCertificateChain()
        {
            return string.Join("", this.CertificateChain);
        }
    }
}