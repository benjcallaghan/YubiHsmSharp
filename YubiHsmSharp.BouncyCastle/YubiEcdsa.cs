using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An ECDSA signer that uses the YubiHSM 2 for signing operations.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// sign-ecdsa.
/// </remarks>
/// <param name="session">The authenticated session with the YubiHSM 2.</param>
public class YubiEcdsa(YubiSession session) : IDsa
{
    private YubiECPrivateKeyParameters? key;

    /// <inheritdoc />
    public string AlgorithmName => "ECDSA";

    /// <inheritdoc />
    public BigInteger Order => this.key?.Parameters.N ?? BigInteger.Zero;

    /// <inheritdoc />
    public void Init(bool forSigning, ICipherParameters parameters)
    {
        if (!forSigning)
        {
            throw new ArgumentException("This cipher only supports signing operations.", nameof(forSigning));
        }

        if (parameters is YubiECPrivateKeyParameters yubiKey)
        {
            this.key = yubiKey;
        }
    }

    /// <inheritdoc />
    public BigInteger[] GenerateSignature(byte[] message)
    {
        if (this.key is null)
        {
            throw new InvalidOperationException("Cipher not initialized for signing. Call Init(true, parameters) with a valid private key before generating signatures.");
        }

        const int maxSignatureLength = 141; // Maximum length of a DER-encoded ECDSA signature for P-521
        Span<byte> signature = stackalloc byte[maxSignatureLength];
        int written = session.SignEcdsa(this.key.KeyId, message, signature);
        signature = signature[..written];

        Asn1Sequence seq = Asn1Sequence.GetInstance(signature.ToArray());        
        BigInteger r = ((DerInteger)seq[0]).Value;
        BigInteger s = ((DerInteger)seq[1]).Value;
        return [r, s];
    }

    /// <inheritdoc />
    public bool VerifySignature(byte[] message, BigInteger r, BigInteger s)
    {
        throw new NotSupportedException("This cipher only supports private key operations. For public key operations, use the standard BouncyCastle ECDSA engine.");
    }
}
