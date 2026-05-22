namespace Aspire.Hosting.ApplicationModel;

public sealed class YubiHsmResource([ResourceName] string name) : IResourceWithConnectionString, IResourceWithEndpoints
{
    private EndpointReference? yubiReference;
    public EndpointReference HttpEndpoint => this.yubiReference ??= new(this, "http");

    public ReferenceExpression ConnectionStringExpression =>
        ReferenceExpression.Create($"http://{this.HttpEndpoint.Property(EndpointProperty.HostAndPort)}");

    public string Name => name;

    public ResourceAnnotationCollection Annotations => throw new NotImplementedException();
}