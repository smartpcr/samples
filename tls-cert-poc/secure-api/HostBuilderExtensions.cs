using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace secure_api
{
    public static class HostBuilderExtensions
    {
        public static IWebHostBuilder UseKestrel(this IWebHostBuilder builder, int port)
        {
            return builder.UseKestrel(options =>
            {
                var kvClient = options.ApplicationServices.GetService<IKeyVaultClient>();
                var vaultSettings = options.ApplicationServices.GetService<IOptions<VaultSettings>>().Value;
                var secretSettings = options.ApplicationServices.GetService<IOptions<SecretSettings>>().Value;

                options.ListenAnyIP(port, listenOptions =>
                {
                    var secretValue = kvClient.GetSecretAsync(vaultSettings.VaultUrl, secretSettings.SslCertName)
                        .GetAwaiter().GetResult().Value;
                    byte[] bytes = System.Convert.FromBase64String(secretValue);
                    X509Certificate2 x509 = new X509Certificate2(bytes);
                    listenOptions.UseHttps(x509);
                });
            });
        }
    }
}