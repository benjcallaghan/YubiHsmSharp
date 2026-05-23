using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using YubiHsmSharp;
using YubiHsmSharp.Client;

namespace Microsoft.Extensions.Hosting;

/// <summary>
/// Contains extension methods for registering YubiHSM clients in an application.
/// </summary>
public static class YubiHsmSharpExtensions
{
    extension(IHostApplicationBuilder builder)
    {
        /// <summary>
        /// Registers 'Scoped' <see cref="YubiSession"/> for communicating with a YubiHSM 2.
        /// </summary>
        /// <param name="connectionName">A name used to retrieve configuration settings.</param>
        /// <param name="configure">An optional delegate that can be used for customizing options.</param>
        public void AddYubiHsmClient(string connectionName, Action<YubiHsmOptions>? configure = null)
        {
            builder.AddYubiHsmClient(YubiHsmOptions.DefaultConfigSectionName, configure, connectionName, serviceKey: null);
        }

        /// <summary>
        /// Registers 'Scoped' <see cref="YubiSession"/> for communicating with a YubiHSM 2.
        /// </summary>
        /// <param name="name">The name of the component, which is used as the <see cref="ServiceDescriptor.ServiceKey"/>,
        /// and also to retrieve configuration settings.</param>
        /// <param name="configure">An optional delegate that can be used for customizing options.</param>
        public void AddKeyedYubiHsmClient(string name, Action<YubiHsmOptions>? configure = null)
        {
            builder.AddYubiHsmClient($"{YubiHsmOptions.DefaultConfigSectionName}:{name}", configure, connectionName: name, serviceKey: name);
        }

        private void AddYubiHsmClient(string configurationSectionName, Action<YubiHsmOptions>? configure, string connectionName, string? serviceKey)
        {
            var options = builder.Services.AddOptions<YubiHsmOptions>(serviceKey)
                .BindConfiguration(configurationSectionName)
                .ValidateDataAnnotations()
                .ValidateOnStart();

            if (configure is not null)
            {
                options = options.Configure(configure);
            }

            builder.Services.TryAddSingleton<YubiModule>();

            if (serviceKey is null)
            {
                builder.Services.AddSingleton(sp => CreateYubiConnector(sp, serviceKey: null));
                builder.Services.AddScoped(sp => CreateYubiSession(sp, serviceKey: null));
            }
            else
            {
                builder.Services.AddKeyedSingleton(serviceKey, CreateYubiConnector);
                builder.Services.AddKeyedScoped(serviceKey, CreateYubiSession);
            }

            using var tempProvider = builder.Services.BuildServiceProvider();
            var settings = tempProvider.GetRequiredService<IOptionsMonitor<YubiHsmOptions>>().Get(serviceKey);

            if (settings.DisableHealthChecks is false)
            {
                builder.Services.AddHealthChecks()
                    .Add(new HealthCheckRegistration(
                        name: serviceKey is null ? "YubiHsm" : $"YubiHsm_{connectionName}",
                        factory: sp =>
                        {
                            var session = serviceKey is null
                                ? sp.GetRequiredService<YubiSession>()
                                : sp.GetRequiredKeyedService<YubiSession>(serviceKey);
                            return new YubiHsmHealthCheck(session);
                        },
                        failureStatus: HealthStatus.Unhealthy,
                        tags: ["yubihsm"]
                    ));
            }
        }

        private static YubiConnector CreateYubiConnector(IServiceProvider serviceProvider, object? serviceKey)
        {
            var module = serviceProvider.GetRequiredService<YubiModule>();
            var options = serviceProvider.GetRequiredService<IOptionsSnapshot<YubiHsmOptions>>().Get((string?)serviceKey);

            Span<byte> utf8Url = stackalloc byte[options.Url.Length + 1]; // Null-terminated
            int written = Encoding.UTF8.GetBytes(options.Url, utf8Url);
            utf8Url = utf8Url[..(written + 1)]; // Null-terminated
            utf8Url[^1] = 0;

            return module.InitConnector(utf8Url);
        }

        private static YubiSession CreateYubiSession(IServiceProvider serviceProvider, object? serviceKey)
        {
            var connector = serviceKey is null
                ? serviceProvider.GetRequiredService<YubiConnector>()
                : serviceProvider.GetRequiredKeyedService<YubiConnector>(serviceKey);
            var options = serviceProvider.GetRequiredService<IOptionsSnapshot<YubiHsmOptions>>().Get((string?)serviceKey);

            if (!connector.HasDevice)
            {
                connector.Connect();
            }

            Span<byte> utf8Password = stackalloc byte[options.Password.Length];
            int written = Encoding.UTF8.GetBytes(options.Password, utf8Password);
            utf8Password = utf8Password[..written];

            return connector.CreateSession(options.AuthKeyId, utf8Password);
        }
    }
}
