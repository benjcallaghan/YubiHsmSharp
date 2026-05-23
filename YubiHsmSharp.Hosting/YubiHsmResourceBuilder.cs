namespace Aspire.Hosting.ApplicationModel;

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
