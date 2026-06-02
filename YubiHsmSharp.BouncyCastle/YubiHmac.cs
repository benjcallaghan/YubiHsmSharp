using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An HMAC that uses the YubiHSM 2 to perform the signing operation.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// sign-hmac.
/// </remarks>
/// <param name="session">The authenticated session with the YubiHSM 2.</param>
public class YubiHmac(YubiSession session) : IMac
{
    private readonly MemoryStream data = new();
    private ushort keyId;
    private Algorithm algorithm;

    /// <inheritdoc />
    public string AlgorithmName => this.algorithm switch
    {
        Algorithm.HmacSha1 => "SHA-1/HMAC",
        Algorithm.HmacSha256 => "SHA-256/HMAC",
        Algorithm.HmacSha384 => "SHA-384/HMAC",
        Algorithm.HmacSha512 => "SHA-512/HMAC",
        _ => throw new NotSupportedException($"Unsupported HMAC algorithm: {this.algorithm}")
    };

    /// <inheritdoc />
    public void BlockUpdate(byte[] input, int inOff, int inLen) => BlockUpdate(input.AsSpan(inOff, inLen));

    /// <inheritdoc />
    public void BlockUpdate(ReadOnlySpan<byte> input) => this.data.Write(input);

    /// <inheritdoc />
    public int DoFinal(byte[] output, int outOff) => DoFinal(output.AsSpan(outOff));

    /// <inheritdoc />
    public int DoFinal(Span<byte> output)
    {
        Span<byte> data = this.data.GetBuffer().AsSpan(0, (int)this.data.Length);
        return session.SignHmac(this.keyId, data, output);
    }

    /// <inheritdoc />
    public int GetMacSize() => this.algorithm switch
    {
        Algorithm.HmacSha1 => 20,
        Algorithm.HmacSha256 => 32,
        Algorithm.HmacSha384 => 48,
        Algorithm.HmacSha512 => 64,
        _ => throw new NotSupportedException($"Unsupported HMAC algorithm: {this.algorithm}")
    };

    /// <inheritdoc />
    public void Init(ICipherParameters parameters)
    {
        if (parameters is YubiHmacKeyParameter yubiKey)
        {
            this.keyId = yubiKey.KeyId;
            this.algorithm = yubiKey.Algorithm;
        }
    }

    /// <inheritdoc />
    public void Reset() => this.data.SetLength(0);

    /// <inheritdoc />
    public void Update(byte input) => this.data.WriteByte(input);
}

/// <summary>
/// An HMAC key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiHmacKeyParameter : KeyParameter
{
    /// <summary>
    /// The object ID of the HMAC key within the YubiHSM 2.
     /// </summary>
    public ushort KeyId { get; set; }

    /// <summary>
    /// The HMAC algorithm to use with the key.
     /// </summary>
    public Algorithm Algorithm { get; set; }

    internal YubiHmacKeyParameter(ushort keyId, Algorithm algorithm, int keyLength) : base(new byte[keyLength])
    {
        this.KeyId = keyId;
        this.Algorithm = algorithm;
    }
}