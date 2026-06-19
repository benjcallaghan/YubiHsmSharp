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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An RSA block cipher that uses the RSA-PSS mode of the YubiHSM 2.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// sign-pss.
/// </remarks>
/// <param name="session">The authenticated session with the YubiHSM 2.</param>
/// <param name="maskGenerationFunction">The mask generation function to use.</param>
public class YubiRsaPss(YubiSession session, Algorithm maskGenerationFunction) : IAsymmetricBlockCipher
{
    private ObjectId keyId;
    private int modulusLength;

    /// <inheritdoc />
    public string AlgorithmName => "RSS-PSS";

    /// <inheritdoc />
    public void Init(bool forEncryption, ICipherParameters parameters)
    {
        if (!forEncryption)
        {
            throw new ArgumentException("YubiRsaPssBlockCipher only supports signing (encryption) operations.", nameof(forEncryption));
        }

        if (parameters is YubiRsaKeyParameters rsaParameters)
        {
            if (!rsaParameters.IsPrivate)
            {
                throw new InvalidKeyException("This cipher only supports private key operations. For public key operations, use the standard BouncyCastle RSA engine.");
            }

            this.keyId = rsaParameters.KeyId;
            this.modulusLength = rsaParameters.Modulus.BitLength / 8;
        }
    }

    /// <inheritdoc />
    public int GetInputBlockSize() => maskGenerationFunction switch
    {
        Algorithm.Mgf1Sha1 => this.modulusLength - 2 * 20 - 2,
        Algorithm.Mgf1Sha256 => this.modulusLength - 2 * 32 - 2,
        Algorithm.Mgf1Sha384 => this.modulusLength - 2 * 48 - 2,
        Algorithm.Mgf1Sha512 => this.modulusLength - 2 * 64 - 2,
        _ => throw new NotSupportedException("Unsupported mask generation function. Supported functions are MGF1 with SHA-1, SHA-256, SHA-384, and SHA-512."),
    };

    /// <inheritdoc />
    public int GetOutputBlockSize() => this.modulusLength;

    /// <inheritdoc />
    public byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen)
    {
        Span<byte> output = stackalloc byte[this.GetOutputBlockSize()];
        int written = session.SignPss(this.keyId, inBuf.AsSpan(inOff, inLen), output, inLen, maskGenerationFunction);
        return output[..written].ToArray();
    }
}