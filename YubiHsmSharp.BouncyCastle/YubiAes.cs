/*
 * Copyright 2026 Benjamin Callaghan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An AES block cipher that uses the AES/ECB mode of the YubiHSM 2.
/// </summary>
/// <remarks>
/// Electronic Code Book (ECB) block mode is used because BouncyCastle handles its own block-chaining modes.
/// The authentication key used to create the session must have the following capabilities:
/// encrypt-ecb (for encryption), decrypt-ecb (for decryption)
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiAes(YubiSession session) : IBlockCipher
{
    private bool forEncryption;
    private ObjectId keyId;

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
        }
    }

    /// <inheritdoc />
    public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
        => this.ProcessBlock(inBuf.AsSpan(inOff), outBuf.AsSpan(outOff));

    /// <inheritdoc />
    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output) => this.forEncryption
        ? session.EncryptAesEcb(this.keyId, input, output)
        : session.DecryptAesEcb(this.keyId, input, output);
}

/// <summary>
/// A symmetric key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiSymmetricKeyParameter : KeyParameter
{
    /// <summary>
    /// The object ID of the symmetric key within the YubiHSM 2.
    /// </summary>
    public ObjectId KeyId { get; }

    // Store an empty array of the correct length so the base KeyLength property is accurate.
    internal YubiSymmetricKeyParameter(ObjectId keyId, int keyLength) : base(new byte[keyLength])
    {
        this.KeyId = keyId;
    }
}

/// <summary>
/// Parameters for generating a new key within the YubiHSM 2, suitable for use with a Yubi/BouncyCastle key generators.
/// </summary>
public class YubiKeyGenerationParameters() : KeyGenerationParameters(new SecureRandom(), 0)
{
    /// <summary>
    /// The label to assign to the generated key.
    /// </summary>
    public required string Label { get; init; }

    /// <summary>
    /// The domains to which the generated key belongs.
    /// </summary>
    public required Domains Domains { get; init; }

    /// <summary>
    /// The capabilities to assign to the generated key.
    /// </summary>
    public required Capabilities Capabilities { get; init; }

    /// <summary>
    /// The algorithm to assign to the generated key.
    /// </summary>
    public required Algorithm Algorithm { get; init; }

    /// <summary>
    /// The ID of the generated key.
    /// </summary>
    public ObjectId KeyId { get; init; }
}

/// <summary>
/// A key generator that creates new AES keys within the YubiHSM 2 device.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// generate-symmetric-key
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiAesKeyGenerator(YubiSession session) : CipherKeyGenerator
{
    private YubiKeyGenerationParameters? parameters;

    /// <summary>
    /// Initializes the key generator with the specified parameters.
    /// </summary>
    /// <param name="parameters">Parameters of type <see cref="YubiKeyGenerationParameters"/>.</param>
    protected override void EngineInit(KeyGenerationParameters parameters)
    {
        this.parameters = parameters as YubiKeyGenerationParameters
            ?? throw new ArgumentException($"Invalid parameters: {parameters}. Expected type: {typeof(YubiKeyGenerationParameters)}", nameof(parameters));
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

        ObjectId keyId = session.GenerateAesKey(
            utf8Label,
            this.parameters.Domains,
            this.parameters.Capabilities,
            this.parameters.Algorithm,
            this.parameters.KeyId
        );

        return session.GetSymmetricKeyParameter(keyId);
    }
}