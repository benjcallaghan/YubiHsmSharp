using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

public static class YubiHsmResourceBuilderExtensions
{
    extension(IDistributedApplicationBuilder builder)
    {
        public IResourceBuilder<YubiHsmResource> AddYubiHsm(string name, string url)
        {
            var external = builder.AddExternalService(name, url);
            return new YubiHsmResourceBuilder(external);
        }
    }

    extension(IResourceBuilder<YubiHsmResource> builder)
    {
        public IResourceBuilder<YubiHsmResource> WithPassword(IResourceBuilder<ParameterResource> authKeyId, IResourceBuilder<ParameterResource> password)
        {
            builder.Resource.AuthKeyId = authKeyId.Resource;
            builder.Resource.Password = password.Resource;
            return builder;
        }
    }

    extension<TDestination>(IResourceBuilder<TDestination> builder) where TDestination : IResourceWithEnvironment
    {
        public IResourceBuilder<TDestination> WithReference(IResourceBuilder<YubiHsmResource> yubihsm)
        {
            return builder.WithReference(yubihsm.Resource.External)
                .WithEnvironment("YubiHsm__AuthKeyId", yubihsm.Resource.AuthKeyId)
                .WithEnvironment("YubiHsm__Password", yubihsm.Resource.Password);
        }
    }
}
