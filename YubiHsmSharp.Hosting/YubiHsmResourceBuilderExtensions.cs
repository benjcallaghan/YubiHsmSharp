using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

public static class YubiHsmResourceBuilderExtensions
{
    extension(IDistributedApplicationBuilder builder)
    {
        public IResourceBuilder<YubiHsmResource> AddYubiHsm(
            [ResourceName] string name,
            string? yubiHsmUrl = null)
        {
            YubiHsmResource resource = new(name);
            return builder.AddResource(resource)
                .WithEndpoint();
        }
    }
}