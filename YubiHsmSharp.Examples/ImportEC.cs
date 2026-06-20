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
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Xunit.Abstractions;

namespace YubiHsmSharp.Examples;

[Trait("Requires", "YubiHSM")]
public class ImportEC(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> p256PrivateKey = """
            -----BEGIN EC PARAMETERS-----
            BggqhkjOPQMBBw==
            -----END EC PARAMETERS-----
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIHj8HDHmb3sE2LbjB4iOkfh2wngiUJX340mzn9viEm/ZoAoGCCqGSM49
            AwEHoUQDQgAESfiuLv9xV/VNf2wLgrMba2jLcjY/DmstGEs2sC9nbR+OhUUia3n1
            f/TdJE466eFZ9MIaZNmRsrkwxWbZ1w7yWQ==
            -----END EC PRIVATE KEY-----
            """u8;
        ReadOnlySpan<byte> keyLabel = "label"u8;
        ReadOnlySpan<byte> password = "password"u8;
        ReadOnlySpan<byte> data = "sudo make me a sandwich"u8;
        ObjectId authKeyId = new(1);

        using YubiModule module = YubiModule.Instance;
        using YubiConnector connector = module.InitConnector(ConnectorUrl.Utf8Value);
        connector.Connect();
        using YubiSession session = connector.CreateSession(authKeyId, password);

        byte sessionId = session.SessionId;
        output.WriteLine($"Successfully established session {sessionId}.");

        using PemReader reader = new(new StreamReader(new MemoryStream(p256PrivateKey.ToArray())));
        AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)reader.ReadObject();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.Private;

        Span<byte> privateKeyData = stackalloc byte[privateKey.D.GetLengthofByteArray()];
        privateKey.D.ToByteArray(privateKeyData);

        Capabilities capabilities = Capabilities.From("sign-ecdsa"u8);
        Domains domainFive = Domains.From("5"u8);
        ObjectId keyId = session.ImportECKey(keyLabel, domainFive, in capabilities, Algorithm.Ecp256, privateKeyData);
        output.WriteLine($"Key imported with ID {keyId}.");

        output.WriteLine($"Data to sign ({data.Length} bytes) is: {Encoding.UTF8.GetString(data)}");
        Span<byte> hashedData = stackalloc byte[32];
        IDigest sha256 = DigestUtilities.GetDigest("SHA256");
        sha256.BlockUpdate(data);
        int written = sha256.DoFinal(hashedData);
        hashedData = hashedData[..written];
        output.WriteLine($"Hash of data ({hashedData.Length} bytes) is: {Convert.ToHexString(hashedData)}");

        Span<byte> signature = stackalloc byte[128];
        written = session.SignEcdsa(keyId, hashedData, signature);
        signature = signature[..written];
        output.WriteLine($"Signature ({signature.Length} bytes) is: {Convert.ToHexString(signature)}");

        // The exported public key is the raw X,Y point on the EC curve.
        // Most parsers expect a 0x04 "uncompressed" flag as the first byte.
        Span<byte> publicKeyData = stackalloc byte[512];
        (_, written) = session.GetPublicKey(keyId, publicKeyData[1..]);
        publicKeyData = publicKeyData[..(written + 1)];
        publicKeyData[0] = 0x04;
        output.WriteLine($"Public key ({publicKeyData.Length} bytes) is: {Convert.ToHexString(publicKeyData)}");

        ECDomainParameters domain = ECDomainParameters.LookupName("secp256r1");
        ECPoint point = domain.Curve.DecodePoint(publicKeyData);
        ECPublicKeyParameters publicKey = new(point, domain);

        // The signature created by YubiHSM is a sequence containing the r and s values (in that order).
        Asn1Sequence seq = Asn1Sequence.GetInstance(signature.ToArray());
        BigInteger r = ((DerInteger)seq[0]).Value;
        BigInteger s = ((DerInteger)seq[1]).Value;

        ECDsaSigner signer = new();
        signer.Init(forSigning: false, publicKey);
        bool verified = signer.VerifySignature(hashedData.ToArray(), r, s);
        Assert.True(verified);
        output.WriteLine("Signature successfully verified.");
    }
}