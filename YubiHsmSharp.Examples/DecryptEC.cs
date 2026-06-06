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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Xunit.Abstractions;

namespace YubiHsmSharp.Examples;

public class DecryptEC(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> keyLabel = "label"u8;
        ReadOnlySpan<byte> password = "password"u8;
        ObjectId authKeyId = new(1);

        using YubiModule module = new();
        using YubiConnector connector = module.InitConnector("http://localhost:12345"u8);
        connector.Connect();
        using YubiSession session = connector.CreateSession(authKeyId, password);

        byte sessionId = session.SessionId;
        output.WriteLine($"Successfully established session {sessionId}.");

        Capabilities capabilities = Capabilities.From("derive-ecdh"u8);
        Domains domainFive = Domains.From("5"u8);
        ObjectId keyId = session.GenerateECKey(keyLabel, domainFive, in capabilities, Algorithm.Ecp256);
        output.WriteLine($"Generated key with ID {keyId}.");

        // The exported public key is the raw X,Y point on the EC curve.
        // Most parsers expect a 0x04 "uncompressed" flag as the first byte.
        Span<byte> publicKeyData = stackalloc byte[512];
        (Algorithm _, int written) = session.GetPublicKey(keyId, publicKeyData[1..]);
        publicKeyData = publicKeyData[..(written + 1)];
        publicKeyData[0] = 0x04;
        output.WriteLine($"Public key ({publicKeyData.Length} bytes) is {Convert.ToHexString(publicKeyData[1..])}");

        ECDomainParameters domain = ECDomainParameters.LookupName("secp256r1");
        ECPoint point = domain.Curve.DecodePoint(publicKeyData);
        ECPublicKeyParameters publicKey = new(point, domain);

        ECKeyPairGenerator generator = new();
        ECDomainParameters peerDomain = ECDomainParameters.LookupName("prime256v1");
        generator.Init(new ECKeyGenerationParameters(peerDomain, new SecureRandom()));
        AsymmetricCipherKeyPair peerKey = generator.GenerateKeyPair();

        ECDHBasicAgreement agreement = new();
        agreement.Init(peerKey.Private);
        BigInteger peerSecret = agreement.CalculateAgreement(publicKey);

        Span<byte> peerPublicKeyData = stackalloc byte[((ECPublicKeyParameters)peerKey.Public).Q.GetEncodedLength(compressed: false)];
        ((ECPublicKeyParameters)peerKey.Public).Q.EncodeTo(compressed: false, peerPublicKeyData);

        Span<byte> computedSecret = stackalloc byte[128];
        written = session.DeriveEcdh(keyId, peerPublicKeyData, computedSecret);
        computedSecret = computedSecret[..written];

        Assert.Equal(peerSecret, new BigInteger(sign: 1, computedSecret));
        output.WriteLine("Secrets match.");
    }
}