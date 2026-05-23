namespace Aspire.Hosting.ApplicationModel;

/// <summary>
/// Represents a YubiHSM 2 resource that can be used by an application.
/// </summary>
public class YubiHsmResource : Resource
{
    private readonly IResourceBuilder<ExternalServiceResource> external;

    internal YubiHsmResource(IResourceBuilder<ExternalServiceResource> external) : base(external.Resource.Name)
    {
        this.external = external;
    }

    internal IResourceBuilder<ExternalServiceResource> External => external;

    internal ParameterResource? AuthKeyId { get; set; }

    internal ParameterResource? Password { get; set; }
}
