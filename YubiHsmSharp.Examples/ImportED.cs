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

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Xunit.Abstractions;

namespace YubiHsmSharp.Examples;

[Trait("Requires", "YubiHSM")]
public class ImportED(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> ed25519PrivateKey = """
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VwBCIEIEzNCJso/5banbbDRuwRTg9bijGfNaumJNqM9u1PuKb7
            -----END PRIVATE KEY-----
            """u8;
        ReadOnlySpan<byte> keyLabel = "label"u8;
        ReadOnlySpan<byte> password = "password"u8;
        ReadOnlySpan<byte> data = [0x72];
        ReadOnlySpan<byte> expectedSignature = [
            0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f,
            0x64, 0x25, 0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76,
            0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99,
            0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae,
            0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00
        ];
        ReadOnlySpan<byte> expectedPublicKey = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89,
            0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e,
            0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c
        ];
        ObjectId authKeyId = new(1);

        using YubiModule module = YubiModule.Instance;
        using YubiConnector connector = module.InitConnector(ConnectorUrl.Utf8Value);
        connector.Connect();
        using YubiSession session = connector.CreateSession(authKeyId, password);

        byte sessionId = session.SessionId;
        output.WriteLine($"Successfully established session {sessionId}.");

        using PemReader reader = new(new StreamReader(new MemoryStream(ed25519PrivateKey.ToArray())));
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)reader.ReadObject();

        Span<byte> privateKeyData = stackalloc byte[32];
        privateKey.Encode(privateKeyData);

        Capabilities capabilities = Capabilities.From("sign-eddsa"u8);
        Domains domainFive = Domains.From("5"u8);
        ObjectId keyId = session.ImportEDKey(keyLabel, domainFive, in capabilities, Algorithm.Ed25519, privateKeyData);
        output.WriteLine($"Key imported with ID {keyId}.");

        output.WriteLine($"Signing {data.Length} bytes of data");
        Span<byte> signature = stackalloc byte[128];
        int written = session.SignEddsa(keyId, data, signature);
        signature = signature[..written];
        output.WriteLine($"Signature ({signature.Length} bytes) is: {Convert.ToHexString(signature)}");
        Assert.Equal(expectedSignature, signature);

        Span<byte> publicKeyData = stackalloc byte[512];
        (_, written) = session.GetPublicKey(keyId, publicKeyData);
        publicKeyData = publicKeyData[..written];
        Assert.Equal(expectedPublicKey, publicKeyData);
        output.WriteLine($"Public key ({publicKeyData.Length} bytes) is: {Convert.ToHexString(publicKeyData)}");
    }
}