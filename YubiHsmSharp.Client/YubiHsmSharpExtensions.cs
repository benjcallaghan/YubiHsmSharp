using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using YubiHsmSharp;
using YubiHsmSharp.Client;

namespace Microsoft.Extensions.Hosting;

/// <summary>
/// Contains extension methods for registering YubiHSM clients in an application.
/// </summary>
public static partial class YubiHsmSharpExtensions
{
    [LoggerMessage(Level = LogLevel.Debug, Message = "{Line}")]
    private static partial void LogConnectorOutput(ILogger logger, string line);

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
                .Configure(settings =>
                {
                    if (builder.Configuration.GetConnectionString(connectionName) is string connectionString)
                    {
                        settings.ParseConnectionString(connectionString);
                    }
                })
                .ValidateDataAnnotations()
                .ValidateOnStart();

            if (configure is not null)
            {
                options = options.Configure(configure);
            }

            builder.Services.TryAddSingleton(CreateYubiModule);

            if (serviceKey is null)
            {
                builder.Services.AddScoped(sp => CreateYubiConnector(sp, serviceKey: null));
                builder.Services.AddScoped(sp => CreateYubiSession(sp, serviceKey: null));
            }
            else
            {
                builder.Services.AddKeyedScoped(serviceKey, CreateYubiConnector);
                builder.Services.AddKeyedScoped(serviceKey, CreateYubiSession);
            }

            using var tempProvider = builder.Services.BuildServiceProvider();
            var settings = tempProvider.GetRequiredService<IOptionsMonitor<YubiHsmOptions>>().Get(serviceKey);

            bool shouldEnableTelemetryService = settings.DisableMetrics is false || settings.DisableDeviceLogs is false;
            if (shouldEnableTelemetryService)
            {
                builder.Services.AddHostedService(sp => new DeviceTelemetryService(
                    sp.GetRequiredService<IServiceScopeFactory>(),
                    sp.GetRequiredService<ILogger<DeviceTelemetryService>>(),
                    sp.GetRequiredService<IOptionsMonitor<YubiHsmOptions>>(),
                    serviceKey));
            }

            if (settings.DisableHealthChecks is false)
            {
                builder.Services.AddHealthChecks()
                    .Add(new HealthCheckRegistration(
                        name: serviceKey is null ? "YubiHsm" : $"YubiHsm_{connectionName}",
                        factory: sp => new YubiHsmHealthCheck(sp, serviceKey),
                        failureStatus: HealthStatus.Unhealthy,
                        tags: ["yubihsm"]
                    ));
            }

            if (settings.DisableMetrics is false)
            {
                builder.Services.AddOpenTelemetry()
                    .WithMetrics(metrics => metrics.AddMeter(DeviceTelemetryService.MeterName));
            }
        }
    }

    private static YubiModule CreateYubiModule(IServiceProvider serviceProvider)
    {
        var logger = serviceProvider.GetRequiredService<ILogger<YubiConnector>>();

        var module = YubiModule.Instance;
        YubiConnector.SetGlobalDebugOutput(line => LogConnectorOutput(logger, line));
        return module;
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
