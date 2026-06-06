using Org.BouncyCastle.Crypto;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An RSA block cipher that uses the RSA-OAEP mode of the YubiHSM 2.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// decrypt-oaep
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
/// <param name="maskGenerationFunction">The mask generation function to use.</param>
public class YubiRsaOaep(YubiSession session, Algorithm maskGenerationFunction) : IAsymmetricBlockCipher
{
    private ObjectId keyId;
    private int modulusLength;

    /// <inheritdoc />
    public string AlgorithmName => "RSA-OAEP";

    /// <inheritdoc />
    public int GetInputBlockSize() => this.modulusLength;

    /// <inheritdoc />
    public int GetOutputBlockSize() => maskGenerationFunction switch
    {
        Algorithm.Mgf1Sha1 => this.modulusLength - 2 * 20 - 2,
        Algorithm.Mgf1Sha256 => this.modulusLength - 2 * 32 - 2,
        Algorithm.Mgf1Sha384 => this.modulusLength - 2 * 48 - 2,
        Algorithm.Mgf1Sha512 => this.modulusLength - 2 * 64 - 2,
        _ => throw new NotSupportedException("Unsupported mask generation function. Supported functions are MGF1 with SHA-1, SHA-256, SHA-384, and SHA-512."),
    };

    /// <inheritdoc />
    public void Init(bool forEncryption, ICipherParameters parameters)
    {
        if (forEncryption)
        {
            throw new NotSupportedException("This cipher only supports private key operations. For public key operations, use the standard BouncyCastle RSA engine.");
        }

        if (parameters is YubiRsaKeyParameters yubiKey)
        {
            if (!yubiKey.IsPrivate)
            {
                throw new NotSupportedException("This cipher only supports private key operations. For public key operations, use the standard BouncyCastle RSA engine.");
            }

            this.keyId = yubiKey.KeyId;
            this.modulusLength = yubiKey.Modulus.BitLength / 8;
        }
    }

    /// <inheritdoc />
    public byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen)
    {
        Span<byte> plaintext = stackalloc byte[this.GetOutputBlockSize()];
        int written = session.DecryptOaep(this.keyId, inBuf.AsSpan(inOff, inLen), plaintext, ""u8, maskGenerationFunction);
        return plaintext[..written].ToArray();
    }
}
