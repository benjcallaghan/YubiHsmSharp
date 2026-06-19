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
    private ObjectId keyId;
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
    public ObjectId KeyId { get; set; }

    /// <summary>
    /// The HMAC algorithm to use with the key.
    /// </summary>
    public Algorithm Algorithm { get; set; }

    internal YubiHmacKeyParameter(ObjectId keyId, Algorithm algorithm, int keyLength) : base(new byte[keyLength])
    {
        this.KeyId = keyId;
        this.Algorithm = algorithm;
    }
}

/// <summary>
/// A key generator that creates new HMAC keys within the YubiHSM 2 device.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// generate-hmac-key
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiHmacKeyGenerator(YubiSession session) : CipherKeyGenerator
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
    /// Generates a new HMAC key and returns it directly.
    /// </summary>
    /// <returns>The generated key.</returns>
    /// <exception cref="NotSupportedException">Always thrown.</exception>
    protected override byte[] EngineGenerateKey()
    {
        throw new NotSupportedException("Generated keys must be stored within the YubiHSM device.");
    }

    /// <summary>
    /// Generates a new HMAC key within the YubiHSM 2.
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

        ObjectId keyId = session.GenerateHmacKey(
            utf8Label,
            this.parameters.Domains,
            this.parameters.Capabilities,
            this.parameters.Algorithm,
            this.parameters.KeyId
        );

        return session.GetHmacKeyParameter(keyId);
    }
}