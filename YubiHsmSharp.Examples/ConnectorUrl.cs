using System.Text;

namespace YubiHsmSharp.Examples;

internal class ConnectorUrl
{
    public static string Value =>
        Environment.GetEnvironmentVariable("DEFAULT_CONNECTOR_URL")
        ?? "http://localhost:12345";
}