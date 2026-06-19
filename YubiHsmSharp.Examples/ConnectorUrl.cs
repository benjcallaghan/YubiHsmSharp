using System.Text;

namespace YubiHsmSharp.Examples;

internal class ConnectorUrl
{
    public static ReadOnlySpan<byte> Utf8Value => Encoding.UTF8.GetBytes(
        Environment.GetEnvironmentVariable("DEFAULT_CONNECTOR_URL")
        ?? "http://localhost:12345");
}