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
            return builder.AddResource(new YubiHsmResource(name, url))
                .WithInitialState(new CustomResourceSnapshot
                {
                    ResourceType = "YubiHsm",
                    Properties = [],
                    CreationTimeStamp = DateTime.UtcNow,
                    IconName = "AzureKeyVault",
                    IconVariant = IconVariant.Regular,
                    State = KnownResourceStates.Running,
                    Urls = [new("Connector", url, IsInternal: true)],                    
                });
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
}
