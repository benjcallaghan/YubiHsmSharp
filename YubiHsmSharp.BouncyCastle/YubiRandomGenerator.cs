using System.Diagnostics;
using Org.BouncyCastle.Crypto.Prng;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// A random number generator that uses the pseudo-random functionality of the YubiHSM 2.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities: get-pseudo-random.
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiRandomGenerator(YubiSession session) : IRandomGenerator
{
    /// <inheritdoc />
    public void AddSeedMaterial(byte[] seed)
    {
        throw new NotSupportedException("YubiHSM 2 does not support seeded random values.");
    }

    /// <inheritdoc />
    public void AddSeedMaterial(ReadOnlySpan<byte> seed)
    {
        throw new NotSupportedException("YubiHSM 2 does not support seeded random values.");
    }

    /// <inheritdoc />
    public void AddSeedMaterial(long seed)
    {
        throw new NotSupportedException("YubiHSM 2 does not support seeded random values.");
    }

    /// <inheritdoc />
    public void NextBytes(byte[] bytes) => NextBytes(bytes.AsSpan());

    /// <inheritdoc />
    public void NextBytes(byte[] bytes, int start, int len) => NextBytes(bytes.AsSpan(start, len));

    /// <inheritdoc />
    public void NextBytes(Span<byte> bytes)
    {
        int written = session.GetPseudoRandom(bytes);
        Debug.Assert(written == bytes.Length);
    }
}