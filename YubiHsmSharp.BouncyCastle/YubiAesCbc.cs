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
using Org.BouncyCastle.Crypto.Parameters;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// An AES block cipher that uses the AES/CBC mode of the YubiHSM 2.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities:
/// encrypt-cbc (for encryption), decrypt-cbc (for decryption)
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiAesCbc(YubiSession session) : IBufferedCipher
{
    private readonly byte[] iv = new byte[16];
    private readonly MemoryStream data = new();
    private bool forEncryption;
    private ObjectId keyId;

    /// <inheritdoc />
    public string AlgorithmName => "AES/CBC";

    /// <inheritdoc />
    public byte[] DoFinal()
    {
        Span<byte> output = stackalloc byte[(int)this.data.Length];
        int written = this.DoFinal(output);
        return output[..written].ToArray();
    }

    /// <inheritdoc />
    public byte[] DoFinal(byte[] input) => this.DoFinal(input, 0, input.Length);

    /// <inheritdoc />
    public byte[] DoFinal(byte[] input, int inOff, int length)
    {
        this.ProcessBytes(input, inOff, length);
        return this.DoFinal();
    }

    /// <inheritdoc />
    public int DoFinal(byte[] output, int outOff)
        => this.DoFinal(output.AsSpan(outOff));

    /// <inheritdoc />
    public int DoFinal(byte[] input, byte[] output, int outOff)
        => this.DoFinal(input.AsSpan(), output.AsSpan(outOff));

    /// <inheritdoc />
    public int DoFinal(byte[] input, int inOff, int length, byte[] output, int outOff)
        => this.DoFinal(input.AsSpan(inOff, length), output.AsSpan(outOff));

    /// <inheritdoc />
    public int DoFinal(Span<byte> output)
    {
        Span<byte> data = this.data.GetBuffer().AsSpan(0, (int)this.data.Length);
        return this.forEncryption
            ? session.EncryptAesCbc(this.keyId, this.iv, data, output)
            : session.DecryptAesCbc(this.keyId, this.iv, data, output);
    }

    /// <inheritdoc />
    public int DoFinal(ReadOnlySpan<byte> input, Span<byte> output)
    {
        this.ProcessBytes(input, []);
        return this.DoFinal(output);
    }

    /// <inheritdoc />
    public int GetBlockSize() => 16;

    /// <inheritdoc />
    public int GetOutputSize(int inputLen) => (int)this.data.Length + inputLen;

    /// <inheritdoc />
    public int GetUpdateOutputSize(int inputLen) => 0;

    /// <inheritdoc />
    public void Init(bool forEncryption, ICipherParameters parameters)
    {
        this.forEncryption = forEncryption;

        if (parameters is ParametersWithIV ivParam)
        {
            ivParam.CopyIVTo(this.iv, 0, this.GetBlockSize());
            parameters = ivParam.Parameters;
        }
        else
        {
            Array.Clear(this.iv);
        }

        if (parameters is YubiSymmetricKeyParameter yubiKey)
        {
            this.keyId = yubiKey.KeyId;
        }
    }

    /// <inheritdoc />
    public byte[] ProcessByte(byte input)
    {
        this.ProcessByte(input, []);
        return [];
    }

    /// <inheritdoc />
    public int ProcessByte(byte input, byte[] output, int outOff)
        => this.ProcessByte(input, output.AsSpan(outOff));

    /// <inheritdoc />
    public int ProcessByte(byte input, Span<byte> output)
    {
        this.data.WriteByte(input);
        return 0;
    }

    /// <inheritdoc />
    public byte[] ProcessBytes(byte[] input)
        => this.ProcessBytes(input, 0, input.Length);

    /// <inheritdoc />
    public byte[] ProcessBytes(byte[] input, int inOff, int length)
    {
        this.ProcessBytes(input.AsSpan(inOff, length), []);
        return [];
    }

    /// <inheritdoc />
    public int ProcessBytes(byte[] input, byte[] output, int outOff)
        => this.ProcessBytes(input.AsSpan(), output.AsSpan(outOff));

    /// <inheritdoc />
    public int ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff)
        => this.ProcessBytes(input.AsSpan(inOff, length), output.AsSpan(outOff));

    /// <inheritdoc />
    public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
    {
        this.data.Write(input);
        return 0;
    }

    /// <inheritdoc />
    public void Reset()
    {
        this.data.SetLength(0);
    }
}