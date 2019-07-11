namespace secure_api
{
    public class VaultSettings
    {
        public string VaultName { get; set; }
        public string ClientId { get; set; }
        public string ClientCertFile { get; set; }
        public string VaultUrl => $"https://{VaultName}.vault.azure.net";
    }
}