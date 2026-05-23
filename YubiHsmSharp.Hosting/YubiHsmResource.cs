namespace Aspire.Hosting.ApplicationModel;

public sealed class YubiHsmResource([ResourceName] string name) : Resource(name),
    IResourceWithEndpoints, IResourceWithConnectionString
{
    internal const string YubiHsmEndpointName = "yubihsm";

    private EndpointReference? yubiHsmEndpoint;
    public EndpointReference YubiHsmEndpoint =>
        this.yubiHsmEndpoint ??= new(this, YubiHsmEndpointName);

    public ReferenceExpression Url =>
        ReferenceExpression.Create($"{this.YubiHsmEndpoint.Property(EndpointProperty.Url)}");

    public ParameterResource? AuthKeyId { get; private set; }

    public ParameterResource? Password { get; private set; }

    public ParameterResource? EncryptionKey { get; private set; }

    public ParameterResource? MacKey { get; private set; }

    public string? EncryptionKeyName { get; private set; }

    public string? MacKeyName { get; private set; }

    public ReferenceExpression ConnectionStringExpression => Url;

    public IEnumerable<KeyValuePair<string, ReferenceExpression>> GetConnectionProperties()
    {
        yield return new("Url", this.Url);

        if (this.AuthKeyId is not null)
        {
            yield return new("AuthKeyId", ReferenceExpression.Create($"{this.AuthKeyId}"));
        }
        if (this.Password is not null)
        {
            yield return new("Password", ReferenceExpression.Create($"{this.Password}"));
        }
        if (this.EncryptionKey is not null)
        {
            yield return new("EncryptionKey", ReferenceExpression.Create($"{this.EncryptionKey}"));
        }
        if (this.MacKey is not null)
        {
            yield return new("MacKey", ReferenceExpression.Create($"{this.MacKey}"));
        }
        if (this.EncryptionKeyName is not null)
        {
            yield return new("EncryptionKeyName", ReferenceExpression.Create($"{this.EncryptionKeyName}"));
        }
        if (this.MacKeyName is not null)
        {
            yield return new("MacKeyName", ReferenceExpression.Create($"{this.MacKeyName}"));
        }
    }

    internal void SetPassword(ParameterResource authKeyId, ParameterResource password)
    {
        this.AuthKeyId = authKeyId;
        this.Password = password;
        this.EncryptionKey = null;
        this.MacKey = null;
        this.EncryptionKeyName = null;
        this.MacKeyName = null;
    }

    internal void SetKeys(ParameterResource authKeyId, ParameterResource encryptionKey, ParameterResource macKey)
    {
        this.AuthKeyId = authKeyId;
        this.Password = null;
        this.EncryptionKey = encryptionKey;
        this.MacKey = macKey;
        this.EncryptionKeyName = null;
        this.MacKeyName = null;
    }

    internal void SetKeyNames(ParameterResource authKeyId, string encryptionKeyName, string macKeyName)
    {
        this.AuthKeyId = authKeyId;
        this.Password = null;
        this.EncryptionKey = null;
        this.MacKey = null;
        this.EncryptionKeyName = encryptionKeyName;
        this.MacKeyName = macKeyName;
    }
}