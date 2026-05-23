var builder = DistributedApplication.CreateBuilder(args);

// var yubihsmExt = builder.AddExternalService("yubihsm", "http://localhost:12345");
// var yubihsm = builder.AddResource(new YubiHsmResource(yubihsmExt));

//var yubihsm = builder.AddYubiHsm("yubihsm");
// var yubihsm = builder.AddResource(new YubiHsmResource("yubihsm"))
//     .WithEndpoint("http", endpoint =>
//     {
//         endpoint.TargetPort = 12345;
//     });

var authKeyId = builder.AddParameter("YubiHsm-AuthKeyId");
var password = builder.AddParameter("YubiHsm-Password");

var yubihsm = AddYubiHsm(builder, "yubihsm", "http://localhost:12345");
WithPassword(yubihsm, authKeyId, password);

var demo = builder.AddProject<Projects.YubiHsmSharp_Demo>("demo");
WithReference(demo, yubihsm);

builder.Build().Run();

IResourceBuilder<YubiHsmResource> AddYubiHsm(IDistributedApplicationBuilder builder, string name, string url)
{
    var external = builder.AddExternalService(name, url);
    return new YubiHsmResourceBuilder(external);
}

IResourceBuilder<YubiHsmResource> WithPassword(IResourceBuilder<YubiHsmResource> builder, IResourceBuilder<ParameterResource> authKeyId, IResourceBuilder<ParameterResource> password)
{
    builder.Resource.AuthKeyId = authKeyId.Resource;
    builder.Resource.Password = password.Resource;
    return builder;
}

IResourceBuilder<TDestination> WithReference<TDestination>(IResourceBuilder<TDestination> builder, IResourceBuilder<YubiHsmResource> yubihsm) where TDestination : IResourceWithEnvironment
{
    return builder.WithReference(yubihsm.Resource.External)
        .WithEnvironment("YubiHsm__AuthKeyId", yubihsm.Resource.AuthKeyId)
        .WithEnvironment("YubiHsm__Password", yubihsm.Resource.Password);
}

internal class YubiHsmResource(IResourceBuilder<ExternalServiceResource> external) : Resource(external.Resource.Name)
{
    public IResourceBuilder<ExternalServiceResource> External => external;

    public ParameterResource AuthKeyId { get; internal set; }

    public ParameterResource Password { get; internal set; }
}

internal class YubiHsmResourceBuilder(IResourceBuilder<ExternalServiceResource> external) : IResourceBuilder<YubiHsmResource>
{
    public IDistributedApplicationBuilder ApplicationBuilder => external.ApplicationBuilder;

    public YubiHsmResource Resource { get; } = new YubiHsmResource(external);

    public IResourceBuilder<YubiHsmResource> WithAnnotation<TAnnotation>(TAnnotation annotation, ResourceAnnotationMutationBehavior behavior = ResourceAnnotationMutationBehavior.Append) where TAnnotation : IResourceAnnotation
    {
        var ext = external.WithAnnotation(annotation, behavior);
        return new YubiHsmResourceBuilder(ext);
    }
}