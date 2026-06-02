using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace YubiHsmSharp.BouncyCastle;

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

        return session.GetSymmetricKeyParameter(keyId);
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