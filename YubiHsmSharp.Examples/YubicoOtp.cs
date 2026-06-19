/*
 * Copyright 2015-2018 Yubico AB
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

using System.Buffers.Binary;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit.Abstractions;

namespace YubiHsmSharp.Examples;

public class YubicoOtp(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> keylabel = "label"u8;
        ReadOnlySpan<byte> password = "password"u8;
        ReadOnlySpan<byte> otpKey = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        ];
        ObjectId authKeyId = new(1);

        using YubiModule module = YubiModule.Instance;
        using YubiConnector connector = module.InitConnector("http://localhost:12345"u8);
        connector.Connect();
        using YubiSession session = connector.CreateSession(authKeyId, password);

        byte sessionId = session.SessionId;
        output.WriteLine($"Successfully established session {sessionId}.");

        Capabilities capabilities = Capabilities.From("create-otp-aead:decrypt-otp:randomize-otp-aead"u8);
        Domains domainFive = Domains.From("5"u8);
        uint nonceId = 0x12345678;
        ObjectId keyId = session.GenerateOtpAeadKey(keylabel, domainFive, in capabilities, Algorithm.Aes128YubicoOtp, nonceId);
        output.WriteLine($"Generated OTP key with ID {keyId}.");

        session.DeleteObject(keyId, ObjectType.OtpAeadKey);
        keyId = session.ImportOtpAeadKey(keylabel, domainFive, in capabilities, nonceId, otpKey, keyId);
        output.WriteLine($"Put OTP key with ID {keyId}.");

        Span<byte> aead = stackalloc byte[512];
#if NET9_0_OR_GREATER
        foreach (var (index, vector) in TestVector.Values.Index())
        {
#else
        for (int index = 0; index < TestVector.Values.Count(); index++)
        {
            TestVector vector = TestVector.Values.ElementAt(index);
#endif
            output.WriteLine($"Checking test vector {index}...");

            int aeadLength = session.CreateOtpAead(keyId, vector.Key.Span, vector.Id.Span, aead);
            OtpCounters vectorCounters = session.DecryptOtp(keyId, aead[..aeadLength], vector.Otp.Span);

            Assert.Equal(vector.UseCounter, vectorCounters.UseCounter);
            Assert.Equal(vector.SessionCounter, vectorCounters.SessionCounter);
            Assert.Equal(vector.TimestampHigh, vectorCounters.TimestampHigh);
            Assert.Equal(vector.TimestampLow, vectorCounters.TimestampLow);

            output.WriteLine("OK");
        }

        Span<byte> otpData = stackalloc byte[64];
        int written = session.RandomizeOtpAead(keyId, otpData);
        otpData = otpData[..written];

        Span<byte> nonce = stackalloc byte[13];
        BinaryPrimitives.WriteUInt32LittleEndian(nonce, nonceId);
        otpData[..6].CopyTo(nonce[4..]);

        const int tagLength = 8;
        IBufferedCipher aesCcm = CipherUtilities.GetCipher("AES128/CCM");
        aesCcm.Init(forEncryption: false, new AeadParameters(new KeyParameter(otpKey), macSize: 16, nonce.ToArray(), associatedText: otpData[^tagLength..].ToArray()));

        Span<byte> outputBuffer = stackalloc byte[32];
        written = aesCcm.DoFinal(otpData[6..^tagLength], outputBuffer);
        outputBuffer = outputBuffer[..written];

        TestToken token = new(
            id: outputBuffer[16..22],
            useCounter: 0xabcd,
            timestampLow: 0xdcba,
            timestampHigh: 0xff,
            sessionCounter: 0x00
        );

        IBufferedCipher aesEcb = CipherUtilities.GetCipher("AES128/ECB");
        aesEcb.Init(forEncryption: true, new KeyParameter(outputBuffer));

        Span<byte> otp = stackalloc byte[16];
        written = aesEcb.DoFinal(token.Raw.Span, otp);
        otp = otp[..written];

        OtpCounters counters = session.DecryptOtp(keyId, otpData, otp);
        Assert.Equal(token.UseCounter, counters.UseCounter);
        Assert.Equal(token.TimestampLow, counters.TimestampLow);
        Assert.Equal(token.TimestampHigh, counters.TimestampHigh);
        Assert.Equal(token.SessionCounter, counters.SessionCounter);
    }
}

internal class TestVector
{
    public static IEnumerable<TestVector> Values = [
        new() {
            Key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
            Id = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
            UseCounter = 0x0001,
            TimestampLow = 0x0001,
            TimestampHigh = 0x01,
            SessionCounter = 0x01,
            Random = 0x0000,
            Crc = 0xfe36,
            Otp = new byte[] { 0x2f, 0x5d, 0x71, 0xa4, 0x91, 0x5d, 0xec, 0x30, 0x4a, 0xa1, 0x3c, 0xcf, 0x97, 0xbb, 0x0d, 0xbb }
        },
        new() {
            Key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
            Id = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
            UseCounter = 0x0001,
            TimestampLow = 0x0001,
            TimestampHigh = 0x01,
            SessionCounter = 0x02,
            Random = 0x0000,
            Crc = 0x1152,
            Otp = new byte[] { 0xcb, 0x71, 0x0b, 0x46, 0x2b, 0x7b, 0x1c, 0x23, 0x10, 0x0c, 0xb2, 0x46, 0x85, 0xb6, 0x4d, 0x33 }
        },
        new() {
            Key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
            Id = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
            UseCounter = 0x0fff,
            TimestampLow = 0x0001,
            TimestampHigh = 0x01,
            SessionCounter = 0x01,
            Random = 0x0000,
            Crc = 0x9454,
            Otp = new byte[] { 0x77, 0x99, 0x78, 0x12, 0x9b, 0xcc, 0x26, 0x42, 0xc8, 0xad, 0xf5, 0xc1, 0x99, 0x81, 0xa0, 0x16 }
        },
        new() {
            Key = new byte[] { 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88 },
            Id = new byte[] { 0x88, 0x88, 0x88, 0x88, 0x88, 0x88 },
            UseCounter = 0x8888,
            TimestampLow = 0x8888,
            TimestampHigh = 0x88,
            SessionCounter = 0x88,
            Random = 0x8888,
            Crc = 0xd3b6,
            Otp = new byte[] { 0x20, 0x76, 0x5f, 0xc6, 0x83, 0xe0, 0xfc, 0x7b, 0x62, 0x42, 0x21, 0x86, 0x48, 0x4d, 0x82, 0x37 }
        },
        new() {
            Key = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            Id = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            UseCounter = 0x0000,
            TimestampLow = 0x0000,
            TimestampHigh = 0x00,
            SessionCounter = 0x00,
            Random = 0x0000,
            Crc = 0xa96a,
            Otp = new byte[] { 0x99, 0x9b, 0x08, 0xbf, 0x0b, 0x3b, 0x98, 0xf8, 0x5b, 0x08, 0x76, 0xa8, 0x77, 0x15, 0x16, 0x16 }
        },
        new() {
            Key = new byte[] { 0xc4, 0x42, 0x28, 0x90, 0x65, 0x30, 0x76, 0xcd, 0xe7, 0x3d, 0x44, 0x9b, 0x19, 0x1b, 0x41, 0x6a },
            Id = new byte[] { 0x33, 0xc6, 0x9e, 0x7f, 0x24, 0x9e },
            UseCounter = 0x0001,
            TimestampLow = 0x13a7,
            TimestampHigh = 0x24,
            SessionCounter = 0x00,
            Random = 0xc63c,
            Crc = 0x1c86,
            Otp = new byte[] { 0x7e, 0x0f, 0xc9, 0x87, 0x35, 0x16, 0x72, 0xc0, 0x70, 0xfa, 0x5c, 0x05, 0x95, 0xec, 0x68, 0xb8 }
        },
    ];

    public ReadOnlyMemory<byte> Key { get; init; }

    public ReadOnlyMemory<byte> Id { get; init; }

    public ushort UseCounter { get; init; }

    public ushort TimestampLow { get; init; }

    public byte TimestampHigh { get; init; }

    public byte SessionCounter { get; init; }

    public ushort Random { get; init; }

    public ushort Crc { get; init; }

    public ReadOnlyMemory<byte> Otp { get; init; }
}

internal class TestToken
{
    public ReadOnlyMemory<byte> Raw { get; }

    public ReadOnlySpan<byte> Id => Raw.Span[..6];

    public ushort UseCounter => BinaryPrimitives.ReadUInt16LittleEndian(Raw.Span[6..]);

    public ushort TimestampLow => BinaryPrimitives.ReadUInt16LittleEndian(Raw.Span[8..]);

    public byte TimestampHigh => Raw.Span[10];

    public byte SessionCounter => Raw.Span[11];

    public ushort Random => BinaryPrimitives.ReadUInt16LittleEndian(Raw.Span[12..]);

    public ushort Crc => BinaryPrimitives.ReadUInt16LittleEndian(Raw.Span[14..]);

    public TestToken(ReadOnlySpan<byte> id, ushort useCounter, ushort timestampLow, byte timestampHigh, byte sessionCounter)
    {
        Memory<byte> raw = new byte[16];
        id.CopyTo(raw.Span);
        BinaryPrimitives.WriteUInt16LittleEndian(raw.Span[6..], useCounter);
        BinaryPrimitives.WriteUInt16LittleEndian(raw.Span[8..], timestampLow);
        raw.Span[10] = timestampHigh;
        raw.Span[11] = sessionCounter;
        // Random value (12..14) is zero.

        ushort crc = 0xffff;
        int bufSize = 14;
        int bufIndex = 0;

        while (bufSize-- > 0)
        {
            int i, j;
            crc ^= (byte)(raw.Span[bufIndex++] & 0xFF);
            for (i = 0; i < 8; i++)
            {
                j = crc & 1;
                crc >>= 1;
                if (j > 0)
                {
                    crc &= 0x8408;
                }
            }
        }

        BinaryPrimitives.WriteUInt16LittleEndian(raw.Span[14..], crc);
    }
}