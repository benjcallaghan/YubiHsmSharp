using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An RSA block cipher that uses the RSA/PKCS#1v1.5 mode of the YubiHSM 2.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// sign-pkcs (for encryption), decrypt-pkcs (for decryption).
/// This cipher requires the RSA private key; thus, it does not support verification of signatures,
/// nor does it support encryption with the public key. For those operations, use the standard BouncyCastle RSA engine.
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiRsaPkcsBlockCipher(YubiSession session) : IAsymmetricBlockCipher
{
    private bool forEncryption;
    private int modulusLength;
    private ushort keyId;

    /// <inheritdoc />
    public string AlgorithmName => "RSA-PKCS#1v1.5";

    /// <inheritdoc />
    public void Init(bool forEncryption, ICipherParameters parameters)
    {
        this.forEncryption = forEncryption;

        if (parameters is YubiRsaKeyParameters rsaKey)
        {
            if (!rsaKey.IsPrivate)
            {
                throw new InvalidKeyException("This cipher only supports private key operations. For public key operations, use the standard BouncyCastle RSA engine.");
            }

            this.keyId = rsaKey.KeyId;
            this.modulusLength = rsaKey.Modulus.BitLength / 8;
        }
    }

    /// <inheritdoc />
    public int GetInputBlockSize() => this.forEncryption ? this.modulusLength - 11 : this.modulusLength;

    /// <inheritdoc />
    public int GetOutputBlockSize() => this.forEncryption ? this.modulusLength : this.modulusLength - 11;

    /// <inheritdoc />
    public byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen)
    {
        Span<byte> output = stackalloc byte[this.GetOutputBlockSize()];
        int written = this.forEncryption
            ? session.SignPkcs1v15(keyId, false, inBuf.AsSpan(inOff, inLen), output)
            : session.DecryptPkcs1v15(keyId, inBuf.AsSpan(inOff, inLen), output);
        return output[..written].ToArray();
    }
}

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