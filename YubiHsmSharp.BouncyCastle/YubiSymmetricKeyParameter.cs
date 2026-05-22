using Org.BouncyCastle.Crypto.Parameters;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// A symmetric key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiSymmetricKeyParameter : KeyParameter
{
    /// <summary>
    /// The object ID of the symmetric key within the YubiHSM 2.
    /// </summary>
    public ushort KeyId { get; }

    // Store an empty array of the correct length so the base KeyLength property is accurate.
    internal YubiSymmetricKeyParameter(ushort keyId, int keyLength) : base(new byte[keyLength])
    {
        this.KeyId = keyId;
    }
}