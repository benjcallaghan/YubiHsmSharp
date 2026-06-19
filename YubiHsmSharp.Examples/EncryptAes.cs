/*
 * Copyright 2021 Yubico AB
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

using Xunit.Abstractions;

namespace YubiHsmSharp.Examples;

public class EncryptAes(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> keyLabel = "label"u8;
        ReadOnlySpan<byte> password = "password"u8;
        ReadOnlySpan<byte> plaintext = "singleblock msg\0"u8;
        ObjectId authKeyId = new(1);

        using YubiModule module = YubiModule.Instance;
        using YubiConnector connector = module.InitConnector(ConnectorUrl.Utf8Value);
        connector.Connect();
        using YubiSession session = connector.CreateSession(authKeyId, password);

        byte sessionId = session.SessionId;
        output.WriteLine($"Successfully established session {sessionId}.");

        DeviceInfo device = connector.GetDeviceInfo();
#if NET10_0_OR_GREATER
        bool ecbSupported = device.Algorithms.Contains(Algorithm.AesEcb);
        bool cbcSupported = device.Algorithms.Contains(Algorithm.AesCbc);
#else
        bool ecbSupported = false;
        bool cbcSupported = false;
        foreach (Algorithm alg in device.Algorithms)
        {
            if (alg == Algorithm.AesEcb)
            {
                ecbSupported = true;
            }
            else if (alg == Algorithm.AesCbc)
            {
                cbcSupported = true;
            }
        }
#endif
        if (!ecbSupported || !cbcSupported)
        {
            output.WriteLine("ECB/CBC unsupported or disabled.");
            return;
        }

        Capabilities capabilities = Capabilities.From("encrypt-ecb,decrypt-ecb,encrypt-cbc,decrypt-cbc"u8);
        Domains domainFive = Domains.From("5"u8);
        ObjectId aesKeyId = session.GenerateAesKey(keyLabel, domainFive, in capabilities, Algorithm.Aes256);
        output.WriteLine($"Generated AES key with ID {aesKeyId}.");

        Span<byte> data = stackalloc byte[16];
        int written = session.EncryptAesEcb(aesKeyId, plaintext, data);
        Assert.False(plaintext.SequenceEqual(data[..written]));
        output.WriteLine("AES-ECB encryption successful");

        written = session.DecryptAesEcb(aesKeyId, data, data);
        Assert.Equal(plaintext, data[..written]);
        output.WriteLine("AES-ECB decryption successful.");

        Span<byte> iv = stackalloc byte[16];
        written = session.GetPseudoRandom(iv);
        iv = iv[..written];

        written = session.EncryptAesCbc(aesKeyId, iv, plaintext, data);
        Assert.False(plaintext.SequenceEqual(data[..written]));
        output.WriteLine("AES-CBC encryption successful.");

        written = session.DecryptAesCbc(aesKeyId, iv, data, data);
        Assert.Equal(plaintext, data[..written]);
        output.WriteLine("AES-CBC decryption successful.");
    }
}