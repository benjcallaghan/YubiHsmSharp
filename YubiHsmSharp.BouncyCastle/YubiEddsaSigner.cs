using Org.BouncyCastle.Crypto;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// A signer for Ed25519 signatures that uses the YubiHSM 2 for signing operations.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// sign-eddsa.
/// </remarks>
/// <param name="session">The authenticated session with the YubiHSM 2.</param>
public class YubiEddsaSigner(YubiSession session) : ISigner
{
    private readonly MemoryStream data = new();
    private ushort keyId;

    /// <inheritdoc />
    public string AlgorithmName => "Ed25519";

    /// <inheritdoc />
    public void Init(bool forSigning, ICipherParameters parameters)
    {
        if (!forSigning)
        {
            throw new ArgumentException("YubiEddsaSigner only supports signing, not verification.", nameof(forSigning));
        }

        if (parameters is YubiEd25519PrivateKeyParameters yubiKey)
        {
            this.keyId = yubiKey.KeyId;
        }
    }

    /// <inheritdoc />
    public void Update(byte input) => this.data.WriteByte(input);

    /// <inheritdoc />
    public void BlockUpdate(byte[] input, int inOff, int inLen) => this.data.Write(input, inOff, inLen);

    /// <inheritdoc />
    public void BlockUpdate(ReadOnlySpan<byte> input) => this.data.Write(input);

    /// <inheritdoc />
    public int GetMaxSignatureSize() => 64;

    /// <inheritdoc />
    public byte[] GenerateSignature()
    {
        Span<byte> data = this.data.GetBuffer().AsSpan(0, (int)this.data.Length);

        Span<byte> signature = stackalloc byte[this.GetMaxSignatureSize()];
        int written = session.SignEddsa(this.keyId, data, signature);
        return signature[..written].ToArray();
    }

    /// <inheritdoc />
    public bool VerifySignature(byte[] signature)
    {
        throw new NotSupportedException("This cipher only supports private key operations. For public key operations, use the standard BouncyCastle Ed25519 engine.");
    }

    /// <inheritdoc />
    public void Reset()
    {
        this.data.SetLength(0);
    }
}
