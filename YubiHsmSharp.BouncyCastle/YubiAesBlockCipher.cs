using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An AES block cipher that uses the AES/ECB mode of the YubiHSM 2.
/// </summary>
/// <remarks>
/// Electronic Code Book (ECB) block mode is used because BouncyCastle handles its own block-chaining modes.
/// </remarks>
public class YubiAesBlockCipher : IBlockCipher
{
    private readonly YubiSession session;
    private bool forEncryption;
    private ushort keyId;

    /// <summary>
    /// Constructs a new block cipher that uses the given <see cref="YubiSession"/> for device communication.
    /// </summary>
    /// <remarks>
    /// The authentication key used to create the session must have the following capabilities:
    /// encrypt-ecb (for encryption), decrypt-ecb (for decryption)
    /// </remarks>
    /// <param name="session">The authenticated session to the YubiHSM 2.</param>
    public YubiAesBlockCipher(YubiSession session)
    {
        this.session = session;
    }

    /// <inheritdoc />
    public string AlgorithmName => "AES";

    /// <inheritdoc />
    public int GetBlockSize() => 16;

    /// <summary>
    /// Initializes the block cipher.
    /// </summary>
    /// <remarks>
    /// Cipher parameters other than <see cref="YubiSymmetricKeyParameter"/> are ignored.
    /// </remarks>
    /// <param name="forEncryption">Initialize for encryption if true, for decryption if false.</param>
    /// <param name="parameters">The <see cref="YubiSymmetricKeyParameter"/> required by the cipher.</param>
    public void Init(bool forEncryption, ICipherParameters parameters)
    {
        this.forEncryption = forEncryption;

        if (parameters is YubiSymmetricKeyParameter yubiKey)
        {
            this.keyId = yubiKey.KeyId;

            // These validations should be performed by the YubiHSM 2 device itself.
            // ObjectDescriptor descriptor = session.GetObject(this.keyId, ObjectType.SymmetricKey);
            // if (!descriptor.Algorithm.IsAes)
            // {
            //     throw new ArgumentException("The provided key must be an AES Symmetric Key.", nameof(parameters));
            // }
            // if (forEncryption && !descriptor.Capabilities.CheckCapability("encrypt-ecb"u8))
            // {
            //     throw new ArgumentException("The provided key must have the 'encrypt-ecb' capability.", nameof(parameters));
            // }
            // if (!forEncryption && !descriptor.Capabilities.CheckCapability("decrypt-ecb"u8))
            // {
            //     throw new ArgumentException("The provided key must have the 'decrypt-ecb' capability.", nameof(parameters));
            // }
        }
    }

    /// <inheritdoc />
    public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
    {
        return this.ProcessBlock(inBuf.AsSpan(inOff), outBuf.AsSpan(outOff));
    }

    /// <inheritdoc />
    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        return this.forEncryption
            ? this.session.EncryptAesEcb(this.keyId, input, output)
            : this.session.DecryptAesEcb(this.keyId, input, output);
    }
}

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