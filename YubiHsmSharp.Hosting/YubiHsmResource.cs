namespace Aspire.Hosting.ApplicationModel;

/// <summary>
/// Represents a YubiHSM 2 resource that can be used by an application.
/// </summary>
public class YubiHsmResource(IResourceBuilder<ExternalServiceResource> external, string url) : Resource(external.Resource.Name)
{
    internal IResourceBuilder<ExternalServiceResource> External => external;

    internal string Url => url;

    internal ParameterResource? AuthKeyId { get; set; }

    internal ParameterResource? Password { get; set; }
}
