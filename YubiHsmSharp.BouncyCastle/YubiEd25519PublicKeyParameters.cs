using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// The public portion of an Ed25519 key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiEd25519PublicKeyParameters : AsymmetricKeyParameter
{
    /// <summary>
    /// The object ID of the asymmetric key within the YubiHSM 2.
    /// </summary>
    public ushort KeyId { get; }

    /// <summary>
    /// The BouncyCastle-compatible public key parameters, containing the public key bytes and associated algorithm information.
    /// </summary>
    // The BouncyCastle type is sealed, so we can't inherit from it directly.
    public Ed25519PublicKeyParameters Parameters { get; }

    internal YubiEd25519PublicKeyParameters(ushort keyId, ReadOnlySpan<byte> publicKey) : base(privateKey: false)
    {
        this.KeyId = keyId;
        this.Parameters = new Ed25519PublicKeyParameters(publicKey.ToArray());
    }
}