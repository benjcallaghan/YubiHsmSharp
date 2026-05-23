using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using YubiHsmSharp;
using YubiHsmSharp.Client;

namespace Microsoft.Extensions.Hosting;

public static class YubiHsmSharpExtensions
{
    extension(IHostApplicationBuilder builder)
    {
        public void AddYubiHsmClient(string connectionName, Action<YubiHsmSharpSettings>? configure = null)
        {
            builder.AddYubiHsmClient(YubiHsmSharpSettings.DefaultConfigSectionName, configure, connectionName, serviceKey: null);
        }

        public void AddKeyedYubiHsmClient(string name, Action<YubiHsmSharpSettings>? configure = null)
        {
            builder.AddYubiHsmClient($"{YubiHsmSharpSettings.DefaultConfigSectionName}:{name}", configure, connectionName: name, serviceKey: name);
        }

        private void AddYubiHsmClient(string configurationSectionName, Action<YubiHsmSharpSettings>? configure, string connectionName, string? serviceKey)
        {
            var options = builder.Services.AddOptionsWithValidateOnStart<YubiHsmSharpSettings>(serviceKey)
                .BindConfiguration(configurationSectionName);

            if (configure is not null)
            {
                options = options.Configure(configure);
            }

            builder.Services.TryAddSingleton<YubiModule>();

            if (serviceKey is null)
            {
                builder.Services.AddSingleton(CreateYubiConnector);
                builder.Services.AddScoped(sp => CreateYubiSession(sp, serviceKey: null));
            }
            else
            {
                builder.Services.AddKeyedSingleton(serviceKey, (sp, key) => CreateYubiConnector(sp));
                builder.Services.AddKeyedScoped(serviceKey, CreateYubiSession);
            }
        }

        private static YubiConnector CreateYubiConnector(IServiceProvider serviceProvider)
        {
            var module = serviceProvider.GetRequiredService<YubiModule>();
            var options = serviceProvider.GetRequiredService<IOptionsSnapshot<YubiHsmSharpSettings>>();

            Span<byte> utf8Url = stackalloc byte[options.Value.Url.Length + 1]; // Null-terminated
            int written = Encoding.UTF8.GetBytes(options.Value.Url, utf8Url);
            utf8Url = utf8Url[..(written + 1)]; // Null-terminated
            utf8Url[^1] = 0;

            return module.InitConnector(utf8Url);
        }

        private static YubiSession CreateYubiSession(IServiceProvider serviceProvider, object? serviceKey)
        {
            var connector = serviceKey is null
                ? serviceProvider.GetRequiredService<YubiConnector>()
                : serviceProvider.GetRequiredKeyedService<YubiConnector>(serviceKey);
            var options = serviceKey is null
                ? serviceProvider.GetRequiredService<IOptionsSnapshot<YubiHsmSharpSettings>>()
                : serviceProvider.GetRequiredKeyedService<IOptionsSnapshot<YubiHsmSharpSettings>>(serviceKey);

            if (!connector.HasDevice)
            {
                connector.Connect();
            }

            Span<byte> utf8Password = stackalloc byte[options.Value.Password.Length];
            int written = Encoding.UTF8.GetBytes(options.Value.Password, utf8Password);
            utf8Password = utf8Password[..written];

            return connector.CreateSession(options.Value.AuthKeyId, utf8Password);
        }
    }
}