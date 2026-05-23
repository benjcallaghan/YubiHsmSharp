using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

/// <summary>
/// Contains extension methods for adding YubiHSM 2 resources to a .NET Aspire Host.
/// </summary>
public static class YubiHsmResourceBuilderExtensions
{
    extension(IDistributedApplicationBuilder builder)
    {
        /// <summary>
        /// Adds a YubiHSM 2 resource as an external service to the distributed application.
        /// </summary>
        /// <param name="name">The name of the resource.</param>
        /// <param name="url">The URL of the YubiHSM 2 service.</param>
        /// <returns>An <see cref="IResourceBuilder{YubiHsmResource}"/> instance.</returns>
        public IResourceBuilder<YubiHsmResource> AddYubiHsm(string name, string url)
        {
            var external = builder.AddExternalService(name, url);
            return new YubiHsmResourceBuilder(external);
        }
    }

    extension(IResourceBuilder<YubiHsmResource> builder)
    {
        /// <summary>
        /// Configures the provided key and password as the authentication mechanism to access the YubiHSM 2 service.
        /// </summary>
        /// <param name="authKeyId">The ID of the authentication key.</param>
        /// <param name="password">The password from which session keys will be derived.</param>
        /// <returns>An <see cref="IResourceBuilder{YubiHsmResource}"/> instance.</returns>
        public IResourceBuilder<YubiHsmResource> WithPassword(IResourceBuilder<ParameterResource> authKeyId, IResourceBuilder<ParameterResource> password)
        {
            builder.Resource.AuthKeyId = authKeyId.Resource;
            builder.Resource.Password = password.Resource;
            return builder;
        }
    }

    extension<TDestination>(IResourceBuilder<TDestination> builder) where TDestination : IResourceWithEnvironment
    {
        /// <summary>
        /// Injects service discovery information for the YubiHSM 2 service into the destination resource.
        /// </summary>
        /// <remarks>
        /// The following properties will be injected as environment variables:
        /// <list type="bullet">
        ///     <item>
        ///         <term>services__{name}__default__0</term>
        ///         <description>The URI of the YubiHSM 2 service, compatible with service discovery.</description>
        ///     </item>       
        ///     <item>
        ///         <term>{name}_AUTHKEYID</term>
        ///         <description>The ID of the authentication key used to connect to the YubiHSM 2 service.</description>
        ///     </item>        
        ///     <item>
        ///         <term>{name}_PASSWORD</term>
        ///         <description>The password used to connect to the YubiHSM 2 service.</description>
        ///     </item>
        /// </list>
        /// </remarks>
        /// <param name="yubihsm">The YubiHSM 2 service to reference.</param>
        /// <returns>The <see cref="IResourceBuilder{TDestination}"/> instance.</returns>
        public IResourceBuilder<TDestination> WithReference(IResourceBuilder<YubiHsmResource> yubihsm)
        {
            builder = builder.WithReference(yubihsm.Resource.External);

            if (yubihsm.Resource.AuthKeyId is not null)
            {
                builder = builder.WithEnvironment($"{yubihsm.Resource.Name.ToUpperInvariant()}_AUTHKEYID", yubihsm.Resource.AuthKeyId);
            }
            if (yubihsm.Resource.Password is not null)
            {
                builder = builder.WithEnvironment($"{yubihsm.Resource.Name.ToUpperInvariant()}_PASSWORD", yubihsm.Resource.Password);
            }

            return builder;
        }
    }
}
