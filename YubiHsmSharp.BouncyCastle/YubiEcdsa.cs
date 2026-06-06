using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

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

/// <summary>
/// An EC private key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiECPrivateKeyParameters : ECPrivateKeyParameters
{
    /// <summary>
    /// The object ID of the asymmetric key within the YubiHSM 2.
    /// </summary>
    public ObjectId KeyId { get; }

    internal YubiECPrivateKeyParameters(ObjectId keyId, ECDomainParameters parameters)
        : base(BigInteger.Zero, parameters)
    {
        this.KeyId = keyId;
    }
}

/// <summary>
/// The public portion of an elliptic curve key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiECPublicKeyParameters : ECPublicKeyParameters
{
    /// <summary>
    /// The object ID of the asymmetric key within the YubiHSM 2.
    /// </summary>
    public ObjectId KeyId { get; }

    internal YubiECPublicKeyParameters(ObjectId keyId, ECPoint q, ECDomainParameters parameters)
        : base(q, parameters)
    {
        this.KeyId = keyId;
    }
}

/// <summary>
/// A key generator that creates new EC keys within the YubiHSM 2 device.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// generate-asymmetric-key
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiEcdsaKeyGenerator(YubiSession session) : IAsymmetricCipherKeyPairGenerator
{
    private YubiKeyGenerationParameters? parameters;

    /// <summary>
    /// Generates a new RSA key pair within the YubiHSM 2 device.
    /// </summary>
    /// <returns>An <see cref="AsymmetricCipherKeyPair"/> representing the generated key pair.</returns>
    public AsymmetricCipherKeyPair GenerateKeyPair()
    {
        if (this.parameters is null)
        {
            throw new InvalidOperationException("Generator not initialized with parameters.");
        }

        Span<byte> utf8Label = stackalloc byte[this.parameters.Label.Length + 1];
        int bytesWritten = Encoding.UTF8.GetBytes(this.parameters.Label, utf8Label);
        utf8Label = utf8Label[..(bytesWritten + 1)];
        utf8Label[^1] = 0;

        ObjectId keyId = session.GenerateECKey(
            utf8Label,
            this.parameters.Domains,
            this.parameters.Capabilities,
            this.parameters.Algorithm,
            this.parameters.KeyId
        );

        return new AsymmetricCipherKeyPair(
            session.GetPublicECParameters(keyId),
            session.GetPrivateECParameters(keyId)
        );
    }

    /// <summary>
    /// Initializes the key generator with the specified parameters.
    /// </summary>
    /// <param name="parameters">Parameters of type <see cref="YubiKeyGenerationParameters"/>.</param>
    public void Init(KeyGenerationParameters parameters)
    {
        this.parameters = parameters as YubiKeyGenerationParameters
            ?? throw new ArgumentException($"Invalid parameters: {parameters}. Expected type: {typeof(YubiKeyGenerationParameters)}", nameof(parameters));
    }
}