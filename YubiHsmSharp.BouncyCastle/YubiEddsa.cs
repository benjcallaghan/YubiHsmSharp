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
/// A signer for Ed25519 signatures that uses the YubiHSM 2 for signing operations.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// sign-eddsa.
/// </remarks>
/// <param name="session">The authenticated session with the YubiHSM 2.</param>
public class YubiEddsa(YubiSession session) : ISigner
{
    private readonly MemoryStream data = new();
    private ObjectId keyId;

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

/// <summary>
/// An Ed25519 private key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiEd25519PrivateKeyParameters : AsymmetricKeyParameter
{
    /// <summary>
    /// The object ID of the asymmetric key within the YubiHSM 2.
    /// </summary>
    public ObjectId KeyId { get; }

    /// <summary>
    /// The BouncyCastle-compatible public key parameters, containing the public key bytes and associated algorithm information.
    /// </summary>
    // The BouncyCastle type is sealed, so we can't inherit from it directly.
    public Ed25519PrivateKeyParameters Parameters { get; }

    internal YubiEd25519PrivateKeyParameters(ObjectId keyId, int keyLength) : base(privateKey: true)
    {
        this.KeyId = keyId;
        this.Parameters = new Ed25519PrivateKeyParameters(new byte[keyLength]);
    }
}

/// <summary>
/// The public portion of an Ed25519 key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiEd25519PublicKeyParameters : AsymmetricKeyParameter
{
    /// <summary>
    /// The object ID of the asymmetric key within the YubiHSM 2.
    /// </summary>
    public ObjectId KeyId { get; }

    /// <summary>
    /// The BouncyCastle-compatible public key parameters, containing the public key bytes and associated algorithm information.
    /// </summary>
    // The BouncyCastle type is sealed, so we can't inherit from it directly.
    public Ed25519PublicKeyParameters Parameters { get; }

    internal YubiEd25519PublicKeyParameters(ObjectId keyId, ReadOnlySpan<byte> publicKey) : base(privateKey: false)
    {
        this.KeyId = keyId;
        this.Parameters = new Ed25519PublicKeyParameters(publicKey);
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
public class YubiEddsaKeyGenerator(YubiSession session) : IAsymmetricCipherKeyPairGenerator
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

        ObjectId keyId = session.GenerateEDKey(
            utf8Label,
            this.parameters.Domains,
            this.parameters.Capabilities,
            this.parameters.Algorithm,
            this.parameters.KeyId
        );

        return new AsymmetricCipherKeyPair(
            session.GetPublicEd25519Parameters(keyId),
            session.GetPrivateEd25519Parameters(keyId)
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