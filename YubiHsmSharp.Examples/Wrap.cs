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

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Xunit.Abstractions;

namespace YubiHsmSharp.Examples;

public class Wrap(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> keyLabel = "label"u8;
        ReadOnlySpan<byte> password = "password"u8;
        ObjectId authKeyId = new(1);

        using YubiModule module = YubiModule.Instance;
        using YubiConnector connector = module.InitConnector(ConnectorUrl.Utf8Value);
        connector.Connect();
        using YubiSession session = connector.CreateSession(authKeyId, password);

        byte sessionId = session.SessionId;
        output.WriteLine($"Successfully established session {sessionId}.");

        Capabilities capabilities = Capabilities.From("export-wrapped:import-wrapped"u8);
        // Delegated capabilities has to match the capabilities of the object we want to export.
        Capabilities delegatedCapabilites = Capabilities.From("sign-ecdsa:sign-eddsa:sign-pkcs:sign-pss:exportable-under-wrap"u8);
        Domains domainFive = Domains.From("5"u8);

        ReadOnlySpan<byte> data = "This is the data to sign"u8;
        Span<byte> hashedData = stackalloc byte[32];
        IDigest sha256 = DigestUtilities.GetDigest("SHA256");
        sha256.BlockUpdate(data);
        int written = sha256.DoFinal(hashedData);
        hashedData = hashedData[..written];

        ObjectId wrappingKeyId = session.GenerateWrapKey(keyLabel, domainFive, in capabilities, Algorithm.Aes256CcmWrap, in delegatedCapabilites);
        output.WriteLine($"Generated wrapping key with ID {wrappingKeyId}.");

        capabilities = delegatedCapabilites; // Delegated capabilities has to match the capabilities of the object we want to export.
        ObjectId keyIdBefore = session.GenerateECKey(keyLabel, domainFive, in capabilities, Algorithm.Ecp256);
        output.WriteLine($"Generated ec key with ID {keyIdBefore}.");

        // The exported public key is the raw X,Y point on the EC curve.
        // Most parsers expect a 0x04 "uncompressed" flag as the first byte.
        Span<byte> publicKeyBefore = stackalloc byte[1024];
        (_, int publicKeyBeforeLength) = session.GetPublicKey(keyIdBefore, publicKeyBefore[1..]);
        publicKeyBefore[0] = 0x04;
        publicKeyBeforeLength++;
        output.WriteLine($"Public ec key before ({publicKeyBeforeLength} bytes) is: {Convert.ToHexString(publicKeyBefore[..publicKeyBeforeLength])}");

        Span<byte> signatureBefore = stackalloc byte[512];
        int signatureBeforeLength = session.SignEcdsa(keyIdBefore, hashedData, signatureBefore);
        output.WriteLine($"ECDSA signature before ({signatureBeforeLength} bytes) is: {Convert.ToHexString(signatureBefore[..signatureBeforeLength])}");

        // The signature created by YubiHSM is a sequence containing the r and s values (in that order).
        Asn1Sequence seq = Asn1Sequence.GetInstance(signatureBefore[..signatureBeforeLength].ToArray());
        BigInteger r = ((DerInteger)seq[0]).Value;
        BigInteger s = ((DerInteger)seq[1]).Value;

        ECDomainParameters domain = ECDomainParameters.LookupName("secp256r1");
        ECPoint point = domain.Curve.DecodePoint(publicKeyBefore[..publicKeyBeforeLength]);
        ECPublicKeyParameters ecPublicKey = new(point, domain);

        ECDsaSigner ecSigner = new();
        ecSigner.Init(forSigning: false, ecPublicKey);
        bool verified = ecSigner.VerifySignature(hashedData.ToArray(), r, s);
        Assert.True(verified);
        output.WriteLine("ECDSA Signature before successfully verified.");

        Span<byte> wrappedObject = stackalloc byte[2048];
        int wrappedObjectLength = session.ExportWrapped(wrappingKeyId, ObjectType.AsymmetricKey, keyIdBefore, wrappedObject);
        output.WriteLine($"Wrapped object ({wrappedObjectLength} bytes) is: {Convert.ToHexString(wrappedObject[..wrappedObjectLength])}");

        session.DeleteObject(keyIdBefore, ObjectType.AsymmetricKey);
        output.WriteLine($"Successfully deleted ec key with ID {keyIdBefore}.");

        Action getPublicKey = () =>
        {
            Span<byte> unused = stackalloc byte[1024];
            _ = session.GetPublicKey(keyIdBefore, unused);
        };
        Assert.Throws<YubiHsmException>(getPublicKey);
        output.WriteLine($"Unable to get public key for ec key with ID {keyIdBefore}.");

        (ObjectType objectTypeAfter, ObjectId keyIdAfter) = session.ImportWrapped(wrappingKeyId, wrappedObject[..wrappedObjectLength]);
        output.WriteLine($"Successfully imported wrapped object with ID {keyIdAfter}.");

        Assert.Equal(ObjectType.AsymmetricKey, objectTypeAfter);
        Assert.Equal(keyIdBefore, keyIdAfter);
        output.WriteLine($"ID {keyIdBefore} and {keyIdAfter} match.");

        // The exported public key is the raw X,Y point on the EC curve.
        // Most parsers expect a 0x04 "uncompressed" flag as the first byte.
        Span<byte> publicKeyAfter = stackalloc byte[1024];
        (_, int publicKeyAfterLength) = session.GetPublicKey(keyIdAfter, publicKeyAfter[1..]);
        publicKeyAfter[0] = 0x04;
        publicKeyAfterLength++;
        output.WriteLine($"Public ec key after ({publicKeyAfterLength} bytes) is: {Convert.ToHexString(publicKeyAfter[..publicKeyAfterLength])}");

        Assert.Equal(publicKeyBefore[..publicKeyBeforeLength], publicKeyAfter[..publicKeyAfterLength]);
        output.WriteLine("Public key before and after match.");

        Span<byte> signatureAfter = stackalloc byte[512];
        int signatureAfterLength = session.SignEcdsa(keyIdAfter, hashedData, signatureAfter);
        output.WriteLine($"ECDSA signature after ({signatureAfterLength} bytes) is: {Convert.ToHexString(signatureAfter[..signatureAfterLength])}");

        point = domain.Curve.DecodePoint(publicKeyAfter[..publicKeyAfterLength]);
        ecPublicKey = new(point, domain);

        ecSigner.Init(forSigning: false, ecPublicKey);
        verified = ecSigner.VerifySignature(hashedData.ToArray(), r, s);
        Assert.True(verified);
        output.WriteLine("ECDSA Signature after successfully verified.");

        ObjectDescriptor @object = session.GetObject(keyIdAfter, ObjectType.AsymmetricKey);
        session.DeleteObject(keyIdAfter, ObjectType.AsymmetricKey);
        output.WriteLine($"Successfully deleted ec key with ID {keyIdAfter}.");

        keyIdBefore = session.GenerateEDKey(keyLabel, domainFive, in capabilities, Algorithm.Ed25519);
        output.WriteLine($"Generated ed25519 key with ID {keyIdBefore}.");

        (_, publicKeyBeforeLength) = session.GetPublicKey(keyIdBefore, publicKeyBefore);
        output.WriteLine($"Public ed25519 key before ({publicKeyBeforeLength} bytes) is: {Convert.ToHexString(publicKeyBefore[..publicKeyBeforeLength])}");

        signatureBeforeLength = session.SignEddsa(keyIdBefore, hashedData, signatureBefore);
        output.WriteLine($"Signature ({signatureBeforeLength} bytes) is: {Convert.ToHexString(signatureBefore[..signatureBeforeLength])}");

        Ed25519PublicKeyParameters edPublicKey = new(publicKeyBefore[..publicKeyBeforeLength]);
        ISigner edSigner = SignerUtilities.GetSigner("ED25519");
        edSigner.Init(forSigning: false, edPublicKey);
        edSigner.BlockUpdate(hashedData);
        verified = edSigner.VerifySignature(signatureBefore[..signatureBeforeLength].ToArray());
        Assert.True(verified);
        output.WriteLine("EDDSA Signature before successfully verified.");

        wrappedObjectLength = session.ExportWrapped(wrappingKeyId, ObjectType.AsymmetricKey, keyIdBefore, wrappedObject);
        output.WriteLine($"Wrapped object ({wrappedObjectLength} bytes) is: {Convert.ToHexString(wrappedObject[..wrappedObjectLength])}");

        session.DeleteObject(keyIdBefore, ObjectType.AsymmetricKey);
        output.WriteLine($"Successfully deleted ed25519 key with ID {keyIdBefore}.");

        Assert.Throws<YubiHsmException>(getPublicKey);
        output.WriteLine($"Unable to get public key for ed25519 key with ID {keyIdBefore}.");

        (objectTypeAfter, keyIdAfter) = session.ImportWrapped(wrappingKeyId, wrappedObject[..wrappedObjectLength]);
        output.WriteLine($"Successfully imported wrapped object with ID {keyIdAfter}");

        Assert.Equal(ObjectType.AsymmetricKey, objectTypeAfter);
        Assert.Equal(keyIdBefore, keyIdAfter);
        output.WriteLine($"ID {keyIdBefore} and {keyIdAfter} match.");

        (_, publicKeyAfterLength) = session.GetPublicKey(keyIdAfter, publicKeyAfter);
        output.WriteLine($"Public ed25519 key after ({publicKeyAfterLength} bytes) is: {Convert.ToHexString(publicKeyAfter[..publicKeyAfterLength])}");

        Assert.Equal(publicKeyBefore[..publicKeyBeforeLength], publicKeyAfter[..publicKeyAfterLength]);
        output.WriteLine("Public key before and after match.");

        signatureAfterLength = session.SignEddsa(keyIdAfter, hashedData, signatureAfter);
        output.WriteLine($"Signature ({signatureAfterLength} bytes) is: {Convert.ToHexString(signatureAfter[..signatureAfterLength])}");

        edSigner.Init(forSigning: false, edPublicKey);
        edSigner.BlockUpdate(hashedData);
        verified = edSigner.VerifySignature(signatureAfter[..signatureAfterLength].ToArray());
        Assert.True(verified);
        output.WriteLine("EDDSA Signature after successfully verified.");

        Assert.Equal(signatureBefore[..signatureBeforeLength], signatureAfter[..signatureAfterLength]);
        output.WriteLine("Signature before and after match.");

        @object = session.GetObject(keyIdAfter, ObjectType.AsymmetricKey);
        session.DeleteObject(keyIdAfter, ObjectType.AsymmetricKey);
        output.WriteLine($"Successfully deleted ed25519 key with ID {keyIdAfter}.");

        keyIdBefore = session.GenerateRsaKey(keyLabel, domainFive, in capabilities, Algorithm.Rsa2048);
        output.WriteLine($"Generated 2048 bit RSA key with ID {keyIdBefore}.");

        (_, publicKeyBeforeLength) = session.GetPublicKey(keyIdBefore, publicKeyBefore);
        output.WriteLine($"Public RSA key before ({publicKeyBeforeLength} bytes) is: {Convert.ToHexString(publicKeyBefore[..publicKeyBeforeLength])}");

        signatureBeforeLength = session.SignPkcs1v15(keyIdBefore, hashed: true, hashedData, signatureBefore);
        output.WriteLine($"Signature ({signatureBeforeLength} bytes) is: {Convert.ToHexString(signatureBefore[..signatureBeforeLength])}");

        RsaKeyParameters rsaPublicKey = new(
            isPrivate: false,
            new BigInteger(sign: 1, publicKeyBefore[..publicKeyBeforeLength]), // The returned public key is only the modulus.
            new BigInteger("0x010001") // YubiHSM 2 uses a hard-coded public exponent.
        );
        ISigner rsaSigner = SignerUtilities.GetSigner("SHA256withRSA");
        rsaSigner.Init(forSigning: false, rsaPublicKey);
        rsaSigner.BlockUpdate(data);
        verified = rsaSigner.VerifySignature(signatureBefore[..signatureBeforeLength].ToArray());
        Assert.True(verified);
        output.WriteLine("RSA signature before successfully verified.");

        wrappedObjectLength = session.ExportWrapped(wrappingKeyId, ObjectType.AsymmetricKey, keyIdBefore, wrappedObject);
        output.WriteLine($"Wrapped object ({wrappedObjectLength} bytes) is: {Convert.ToHexString(wrappedObject[..wrappedObjectLength])}");

        session.DeleteObject(keyIdBefore, ObjectType.AsymmetricKey);
        output.WriteLine($"Successfully deleted RSA key with ID {keyIdBefore}.");

        Assert.Throws<YubiHsmException>(getPublicKey);
        output.WriteLine($"Unable to get public key for RSA key with ID {keyIdBefore}.");

        (objectTypeAfter, keyIdAfter) = session.ImportWrapped(wrappingKeyId, wrappedObject);
        output.WriteLine($"Successfully imported wrapped object with ID {keyIdAfter}.");

        Assert.Equal(ObjectType.AsymmetricKey, objectTypeAfter);
        Assert.Equal(keyIdBefore, keyIdAfter);
        output.WriteLine($"ID {keyIdBefore} and {keyIdAfter} match.");

        (_, publicKeyAfterLength) = session.GetPublicKey(keyIdAfter, publicKeyAfter);
        output.WriteLine($"Public RSA key after ({publicKeyAfterLength} bytes) is: {Convert.ToHexString(publicKeyAfter[..publicKeyAfterLength])}");

        Assert.Equal(publicKeyBefore[..publicKeyBeforeLength], publicKeyAfter[..publicKeyAfterLength]);
        output.WriteLine("Public key before and after match.");

        signatureAfterLength = session.SignPkcs1v15(keyIdAfter, hashed: true, hashedData, signatureAfter);
        output.WriteLine($"Signature ({signatureAfterLength} bytes) is: {Convert.ToHexString(signatureAfter[..signatureAfterLength])}");

        rsaPublicKey = new(
            isPrivate: false,
            new BigInteger(sign: 1, publicKeyAfter[..publicKeyAfterLength]), // The returned public key is only the modulus.
            new BigInteger("0x010001") // YubiHSM 2 uses a hard-coded public exponent.
        );
        rsaSigner.Init(forSigning: false, rsaPublicKey);
        rsaSigner.BlockUpdate(data);
        verified = rsaSigner.VerifySignature(signatureAfter[..signatureAfterLength].ToArray());
        Assert.True(verified);
        output.WriteLine("RSA signature after successfully verified.");

        @object = session.GetObject(keyIdAfter, ObjectType.AsymmetricKey);
        session.DeleteObject(keyIdAfter, ObjectType.AsymmetricKey);
        output.WriteLine($"Successfully deleted RSA key with ID {keyIdAfter}.");
    }
}