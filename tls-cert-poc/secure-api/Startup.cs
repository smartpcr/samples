using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace secure_api
{
    public class Startup
    {
        private readonly ILogger<Startup> _logger;
        private readonly ILoggerFactory _loggerFactory;
        public IConfiguration Configuration { get; private set; }
        public IHostingEnvironment Env { get; }

        public Startup(IHostingEnvironment env, ILoggerFactory loggerFactory, IConfiguration configuration)
        {
            Env = env;
            _loggerFactory = loggerFactory;
            _logger = loggerFactory.CreateLogger<Startup>();

            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<VaultSetting>(Configuration.GetSection("Vault"));
            IKeyVaultClient keyVaultClient;
            if (Env.IsProduction())
            {
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                keyVaultClient = new KeyVaultClient(
                    new KeyVaultClient.AuthenticationCallback(
                        azureServiceTokenProvider.KeyVaultTokenCallback));
            }
            else
            {
                var vaultSetting = new VaultSetting();
                Configuration.Bind("Vault", vaultSetting);

                KeyVaultClient.AuthenticationCallback callback = async (authority, resource, scope) =>
                {
                    var authContext = new AuthenticationContext(authority, TokenCache.DefaultShared);
                    var certificate = new X509Certificate2(vaultSetting.CertFile);
                    var clientCred = new ClientAssertionCertificate(vaultSetting.ClientId, certificate);
                    var result = await authContext.AcquireTokenAsync(resource, clientCred);
                    return result.AccessToken;
                };
                keyVaultClient = new KeyVaultClient(callback);
            }
            services.AddSingleton(keyVaultClient);

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseMvc();
        }
    }
}
