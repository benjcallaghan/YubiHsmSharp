namespace Aspire.Hosting.ApplicationModel;

/// <summary>
/// Represents a YubiHSM 2 resource that can be used by an application.
/// </summary>
public class YubiHsmResource(string name, string url) : Resource(name), IResourceWithConnectionString
{
    internal string Url => url;

    internal ParameterResource? AuthKeyId { get; set; }

    internal ParameterResource? Password { get; set; }

    /// <inheritdoc />
    public ReferenceExpression ConnectionStringExpression => ReferenceExpression.Create(
        $"Url={this.Url};AuthKeyId={this.AuthKeyId!};Password={this.Password!}" 
    );
}
