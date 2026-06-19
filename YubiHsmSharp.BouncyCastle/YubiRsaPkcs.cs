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
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An RSA block cipher that uses the RSA/PKCS#1v1.5 mode of the YubiHSM 2.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// sign-pkcs (for encryption), decrypt-pkcs (for decryption).
/// This cipher requires the RSA private key; thus, it does not support verification of signatures,
/// nor does it support encryption with the public key. For those operations, use the standard BouncyCastle RSA engine.
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiRsaPkcs(YubiSession session) : IAsymmetricBlockCipher
{
    private bool forEncryption;
    private int modulusLength;
    private ObjectId keyId;

    /// <inheritdoc />
    public string AlgorithmName => "RSA-PKCS#1v1.5";

    /// <inheritdoc />
    public void Init(bool forEncryption, ICipherParameters parameters)
    {
        this.forEncryption = forEncryption;

        if (parameters is YubiRsaKeyParameters rsaKey)
        {
            if (!rsaKey.IsPrivate)
            {
                throw new InvalidKeyException("This cipher only supports private key operations. For public key operations, use the standard BouncyCastle RSA engine.");
            }

            this.keyId = rsaKey.KeyId;
            this.modulusLength = rsaKey.Modulus.BitLength / 8;
        }
    }

    /// <inheritdoc />
    public int GetInputBlockSize() => this.forEncryption ? this.modulusLength - 11 : this.modulusLength;

    /// <inheritdoc />
    public int GetOutputBlockSize() => this.forEncryption ? this.modulusLength : this.modulusLength - 11;

    /// <inheritdoc />
    public byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen)
    {
        Span<byte> output = stackalloc byte[this.GetOutputBlockSize()];
        int written = this.forEncryption
            ? session.SignPkcs1v15(keyId, false, inBuf.AsSpan(inOff, inLen), output)
            : session.DecryptPkcs1v15(keyId, inBuf.AsSpan(inOff, inLen), output);
        return output[..written].ToArray();
    }
}

/// <summary>
/// An RSA key, stored within a YubiHSM 2, suitable for use in Yubi/BouncyCastle ciphers.
/// </summary>
public class YubiRsaKeyParameters : RsaKeyParameters
{
    /// <summary>
    /// The object ID of the asymmetric key within the YubiHSM 2.
    /// </summary>
    public ObjectId KeyId { get; }

    internal YubiRsaKeyParameters(ObjectId keyId, int keyLength)
        : base(isPrivate: true, new BigInteger(new byte[keyLength]), new BigInteger(new byte[keyLength]))
    {
        this.KeyId = keyId;
    }

    internal YubiRsaKeyParameters(ObjectId keyId, BigInteger modulus, BigInteger exponent)
        : base(isPrivate: false, modulus, exponent)
    {
        this.KeyId = keyId;
    }
}

/// <summary>
/// A key generator that creates new RSA keys within the YubiHSM 2 device.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// generate-asymmetric-key
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiRsaKeyGenerator(YubiSession session) : IAsymmetricCipherKeyPairGenerator
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

        ObjectId keyId = session.GenerateRsaKey(
            utf8Label,
            this.parameters.Domains,
            this.parameters.Capabilities,
            this.parameters.Algorithm,
            this.parameters.KeyId
        );

        return new AsymmetricCipherKeyPair(
            session.GetPublicRsaParameters(keyId),
            session.GetPrivateRsaParameters(keyId)
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