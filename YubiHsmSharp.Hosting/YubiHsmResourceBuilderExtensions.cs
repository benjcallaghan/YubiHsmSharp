using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

public static class YubiHsmResourceBuilderExtensions
{
    extension(IDistributedApplicationBuilder builder)
    {
        public IResourceBuilder<YubiHsmResource> AddYubiHsm([ResourceName] string name)
        {
            YubiHsmResource resource = new(name);
            return builder.AddResource(resource);
        }
    }

    extension(IResourceBuilder<YubiHsmResource> builder)
    {
        public IResourceBuilder<YubiHsmResource> WithHttpEndpoint(string targetHost = "localhost", int targetPort = 12345)
        {
            return builder.WithEndpoint(YubiHsmResource.YubiHsmEndpointName, e =>
            {
                e.TargetHost = targetHost;
                e.TargetPort = targetPort;
                e.UriScheme = "http";
            });
        }

        public IResourceBuilder<YubiHsmResource> WithUsbEndpoint()
        {
            return builder.WithEndpoint(name: YubiHsmResource.YubiHsmEndpointName, scheme: "yhusb");
        }

        public IResourceBuilder<YubiHsmResource> WithPassword(IResourceBuilder<ParameterResource> authKeyId, IResourceBuilder<ParameterResource> password)
        {
            builder.Resource.SetPassword(authKeyId.Resource, password.Resource);
            return builder;
        }

        public IResourceBuilder<YubiHsmResource> WithKeys(IResourceBuilder<ParameterResource> authKeyId, IResourceBuilder<ParameterResource> encryptionKey, IResourceBuilder<ParameterResource> macKey)
        {
            builder.Resource.SetKeys(authKeyId.Resource, encryptionKey.Resource, macKey.Resource);
            return builder;
        }

        public IResourceBuilder<YubiHsmResource> WithNamedKeys(IResourceBuilder<ParameterResource> authKeyId, string encryptionKeyName, string macKeyName)
        {
            builder.Resource.SetKeyNames(authKeyId.Resource, encryptionKeyName, macKeyName);
            return builder;
        }
    }
}
