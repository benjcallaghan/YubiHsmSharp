using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An Ed25519 private key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiEd25519PrivateKeyParameters : AsymmetricKeyParameter
{
    /// <summary>
    /// The object ID of the asymmetric key within the YubiHSM 2.
    /// </summary>
    public ushort KeyId { get; }

    /// <summary>
    /// The BouncyCastle-compatible public key parameters, containing the public key bytes and associated algorithm information.
    /// </summary>
    // The BouncyCastle type is sealed, so we can't inherit from it directly.
    public Ed25519PrivateKeyParameters Parameters { get; }

    internal YubiEd25519PrivateKeyParameters(ushort keyId, int keyLength) : base(privateKey: true)
    {
        this.KeyId = keyId;
        this.Parameters = new Ed25519PrivateKeyParameters(new byte[keyLength]);
    }
}