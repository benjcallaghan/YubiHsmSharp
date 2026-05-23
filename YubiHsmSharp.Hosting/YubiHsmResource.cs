namespace Aspire.Hosting.ApplicationModel;

public class YubiHsmResource(IResourceBuilder<ExternalServiceResource> external) : Resource(external.Resource.Name)
{
    public IResourceBuilder<ExternalServiceResource> External => external;

    public ParameterResource AuthKeyId { get; internal set; }

    public ParameterResource Password { get; internal set; }
}
