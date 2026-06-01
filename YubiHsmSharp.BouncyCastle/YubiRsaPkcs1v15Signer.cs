using Org.BouncyCastle.Crypto;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An RSA PKCS#1 v1.5 signer that uses a YubiHSM 2 for cryptographic operations.
/// </summary>
/// <remarks>
/// The authentication key used to open the session must have the following capabilities:
/// sign-pkcs1v15.
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiRsaPkcs1v15Signer(YubiSession session) : ISigner
{
    private readonly MemoryStream data = new();
    private ushort keyId;
    private bool forSigning;

    /// <inheritdoc />
    public string AlgorithmName => "RSASSA-PKCS1-v1_5";

    /// <inheritdoc />
    public void BlockUpdate(byte[] input, int inOff, int inLen) => this.BlockUpdate(input.AsSpan(inOff, inLen));

    /// <inheritdoc />
    public void BlockUpdate(ReadOnlySpan<byte> input) =>
        // YubiHSM requires all data up front, so we'll buffer it here and then process it in GenerateSignature.
        this.data.Write(input);

    /// <inheritdoc />
    public byte[] GenerateSignature()
    {
        if (!this.forSigning)
        {
            throw new InvalidOperationException("Cannot generate signature when signer is initialized for verification.");
        }

        Span<byte> signature = stackalloc byte[this.GetMaxSignatureSize()];
        int written = this.GenerateSignature(signature);
        return signature[..written].ToArray();
    }

    private int GenerateSignature(Span<byte> signature)
    {
        var dataSpan = this.data.GetBuffer().AsSpan(0, (int)this.data.Length);
        return session.SignPkcs1v15(keyId, hashed: true, dataSpan, signature);
    }

    /// <inheritdoc />
    public int GetMaxSignatureSize() => 512; // YubiHSM 2 supports up to 4096-bit RSA keys, which produce 512-byte signatures.

    /// <inheritdoc />
    public void Init(bool forSigning, ICipherParameters parameters)
    {
        this.forSigning = forSigning;
        if (parameters is YubiAsymmetricKeyParameter keyParameter)
        {
            this.keyId = keyParameter.KeyId;
        }
    }

    /// <inheritdoc />
    public void Reset()
    {
        this.data.SetLength(0);
    }

    /// <inheritdoc />
    public void Update(byte input) => this.data.WriteByte(input);

    /// <inheritdoc />
    public bool VerifySignature(byte[] signature)
    {
        if (this.forSigning)
        {
            throw new InvalidOperationException("Cannot verify signature when signer is initialized for signing.");
        }

        Span<byte> calculated = stackalloc byte[this.GetMaxSignatureSize()];
        int written = this.GenerateSignature(signature);
        calculated = calculated[..written];
        return calculated.SequenceEqual(signature);
    }
}
