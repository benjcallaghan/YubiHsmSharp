using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// A data wrapper using the Wrap mode of the YubiHSM 2.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// wrap-data (for wrapping), unwrap-data (for unwrapping)
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiWrap(YubiSession session) : IWrapper
{
    private ushort keyId;

    /// <inheritdoc />
    public string AlgorithmName => "AES/CCM";

    /// <inheritdoc />
    public void Init(bool forWrapping, ICipherParameters parameters)
    {
        if (parameters is YubiWrapKeyParameter yubiKey)
        {
            this.keyId = yubiKey.KeyId;
        }
    }

    /// <inheritdoc />
    public byte[] Unwrap(byte[] input, int inOff, int length)
    {
        Span<byte> unwrapped = stackalloc byte[length]; // Unwrapped data should be smaller than wrapped data.
        int written = session.UnwrapData(this.keyId, input.AsSpan(inOff, length), unwrapped);
        return unwrapped[..written].ToArray();
    }

    /// <inheritdoc />
    public byte[] Wrap(byte[] input, int inOff, int length)
    {
         // Wrapped data should be larger, but unknown how much larger.
        const int nonceLength = 13;
        const int macLength = 16;
        Span<byte> wrapped = stackalloc byte[(length + nonceLength + macLength) * 2];
        int written = session.WrapData(this.keyId, input.AsSpan(inOff, length), wrapped);
        return wrapped[..written].ToArray();
    }
}

/// <summary>
/// A key generator that creates new symmetric Wrap keys within the YubiHSM 2 device.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// generate-wrap-key
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiWrapKeyGenerator(YubiSession session) : CipherKeyGenerator
{
    private YubiDelegationKeyGenerationParameters? parameters;

    /// <summary>
    /// Initializes the key generator with the specified parameters.
    /// </summary>
    /// <param name="parameters">Parameters of type <see cref="YubiDelegationKeyGenerationParameters"/>.</param>
    protected override void EngineInit(KeyGenerationParameters parameters)
    {
        this.parameters = parameters as YubiDelegationKeyGenerationParameters
            ?? throw new ArgumentException($"Invalid parameters: {parameters}. Expected type: {typeof(YubiDelegationKeyGenerationParameters)}", nameof(parameters));
    }

    /// <summary>
    /// Generates a new symmetric key and returns it directly.
    /// </summary>
    /// <returns>The generated key.</returns>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    protected override byte[] EngineGenerateKey()
    {
        throw new NotSupportedException("Generated keys must be stored within the YubiHSM device.");
    }

    /// <summary>
    /// Generates a new symmetric key within the YubiHSM 2.
    /// </summary>
    /// <returns>A parameter representing the generated key.</returns>
    protected override KeyParameter EngineGenerateKeyParameter()
    {
        if (this.parameters is null)
        {
            throw new InvalidOperationException("Generator not initialized with parameters.");
        }

        Span<byte> utf8Label = stackalloc byte[this.parameters.Label.Length + 1];
        int bytesWritten = Encoding.UTF8.GetBytes(this.parameters.Label, utf8Label);
        utf8Label = utf8Label[..(bytesWritten + 1)];
        utf8Label[^1] = 0;

        ushort keyId = session.GenerateWrapKey(
            utf8Label,
            this.parameters.Domains,
            this.parameters.Capabilities,
            this.parameters.Algorithm,
            this.parameters.DelegatedCapabilities,
            this.parameters.KeyId
        );

        return session.GetWrapKeyParameter(keyId);
    }
}

/// <summary>
/// A wrap key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiWrapKeyParameter : KeyParameter
{
    /// <summary>
    /// The object ID of the wrap key within the YubiHSM 2.
    /// </summary>
    public ushort KeyId { get; }

    // Store an empty array of the correct length so the base KeyLength property is accurate.
    internal YubiWrapKeyParameter(ushort keyId, int keyLength) : base(new byte[keyLength])
    {
        this.KeyId = keyId;
    }
}

/// <summary>
/// Parameters for generating a new key with delegated capabilities within the YubiHSM 2,
/// suitable for use with a Yubi/BouncyCastle key generators.
/// </summary>
public class YubiDelegationKeyGenerationParameters : YubiKeyGenerationParameters
{
    /// <summary>
    /// The delegated capabilites of the generated key.
    /// </summary>
    public required Capabilities DelegatedCapabilities { get; init; }
}