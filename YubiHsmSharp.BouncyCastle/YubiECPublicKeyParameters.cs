using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// The public portion of an elliptic curve key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiECPublicKeyParameters : ECPublicKeyParameters
{
    /// <summary>
    /// The object ID of the asymmetric key within the YubiHSM 2.
    /// </summary>
    public ushort KeyId { get; }

    internal YubiECPublicKeyParameters(ushort keyId, ECPoint q, ECDomainParameters parameters)
        : base(q, parameters)
    {
        this.KeyId = keyId;
    }
}