using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An EC private key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiECPrivateKeyParameters : ECPrivateKeyParameters
{
    /// <summary>
    /// The object ID of the asymmetric key within the YubiHSM 2.
    /// </summary>
    public ushort KeyId { get; }

    internal YubiECPrivateKeyParameters(ushort keyId, ECDomainParameters parameters)
        : base(BigInteger.Zero, parameters)
    {
        this.KeyId = keyId;
    }
}