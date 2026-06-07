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

using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Xunit.Abstractions;

namespace YubiHsmSharp.Examples;

public class GenerateRsa(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> keyLabel = "label"u8;
        ReadOnlySpan<byte> password = "password"u8;
        ReadOnlySpan<byte> data = "sudo make me a sandwich"u8;
        ObjectId authKeyId = new(1);

        using YubiModule module = YubiModule.Instance;
        using YubiConnector connector = module.InitConnector("http://localhost:12345"u8);
        connector.Connect();
        using YubiSession session = connector.CreateSession(authKeyId, password);

        byte sessionId = session.SessionId;
        output.WriteLine($"Successfully established session {sessionId}.");

        Capabilities capabilities = Capabilities.From("sign-pkcs"u8);
        Domains domainFive = Domains.From("5"u8);
        ObjectId keyId = session.GenerateRsaKey(keyLabel, domainFive, in capabilities, Algorithm.Rsa2048);
        output.WriteLine($"Generated key with ID {keyId}.");

        output.WriteLine($"Data to sign ({data.Length} bytes) is: {Encoding.UTF8.GetString(data)}");

        Span<byte> hashedData = stackalloc byte[32];
        IDigest sha256 = DigestUtilities.GetDigest("SHA256");
        sha256.BlockUpdate(data);
        int written = sha256.DoFinal(hashedData);
        hashedData = hashedData[..written];
        output.WriteLine($"Hash of data ({hashedData.Length} bytes) is: {Convert.ToHexString(hashedData)}");

        Span<byte> signature = stackalloc byte[512];
        written = session.SignPkcs1v15(keyId, hashed: true, hashedData, signature);
        signature = signature[..written];
        output.WriteLine($"Signature ({signature.Length} bytes) is: {Convert.ToHexString(signature)}");

        Span<byte> publicKeyData = stackalloc byte[512];
        (_, written) = session.GetPublicKey(keyId, publicKeyData);
        publicKeyData = publicKeyData[..written];
        output.WriteLine($"Public key ({publicKeyData.Length} bytes) is: {Convert.ToHexString(publicKeyData)}");

        RsaKeyParameters rsaPublicKey = new(
            isPrivate: false,
            new BigInteger(sign: 1, publicKeyData), // The returned public key is only the modulus.
            new BigInteger("0x010001") // YubiHSM 2 uses a hard-coded public exponent.
        );
        ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
        signer.Init(forSigning: false, rsaPublicKey);
        signer.BlockUpdate(data);
        bool isVerified = signer.VerifySignature(signature.ToArray());
        Assert.True(isVerified);
        output.WriteLine("Signature successfully verified");
    }
}