using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An RSA key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiRsaKeyParameters : RsaKeyParameters
{
    /// <summary>
    /// The object ID of the asymmetric key within the YubiHSM 2.
    /// </summary>
    public ushort KeyId { get; }

    internal YubiRsaKeyParameters(ushort keyId, int keyLength)
        : base(isPrivate: true, new BigInteger(new byte[keyLength]), new BigInteger(new byte[keyLength]))
    {
        this.KeyId = keyId;
    }

    internal YubiRsaKeyParameters(ushort keyId, BigInteger modulus, BigInteger exponent)
        : base(isPrivate: false, modulus, exponent)
    {
        this.KeyId = keyId;
    }
}