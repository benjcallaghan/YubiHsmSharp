namespace YubiHsmSharp;

/// <summary>
/// A collection of Domains, logical partitions that can be conceptually mapped to a container.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public readonly struct Domains
{
    private readonly ushort domains;
}