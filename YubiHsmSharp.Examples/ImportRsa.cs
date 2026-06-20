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
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Xunit.Abstractions;

namespace YubiHsmSharp.Examples;

[Trait("Requires", "YubiHSM")]
public class ImportRsa(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> rsa2048PrivateKey = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIEowIBAAKCAQEA1LILtPHUKTGvzNKpNHCSmRfE54NoabtPtV/SqAI/6VFT1PIf
            dLBUsBL19g4yAfnyOSTo5o8CYl6LzfdPgkyESXKzOYCKuBDEn14yQ/F1vzzydl5G
            a65dESVCFKUELu9IJwX1hjXpHLkwb9Wj8Z4h/Uikn6Xh3C6GvVOIJZGb9Kjcz+Mo
            Kx9IFAFAIWDV88DKUG9EontXYq4p2Vk6/XvAW63eQPWjUWeOSUiQp8UWtWA3SMZ9
            GwxUh9ZRyd4gw1kqcrqMzwbJyEtmjBbYNnIGPYDCkr4YQJIoGPwNq6hh2HGa1J+M
            EYYZWVbl2GOW1FVMn75q45tnaCaWOlT0H7Om/wIDAQABAoIBAByVHJuhT9iFU9Gb
            kZ95bUnjdtOBxjtHL6v5B48KVlpdUn2wV+fPdmH++kyplbDMTO++9QleuHxNpk30
            aRvieniAUHNuwbWAk1uzRd/5h9A+OXsMqjv4P4t5TUsG7ev8vd54n4j8n6n7fPXa
            aOCkVn76Dx1hJlv3aKXynr4ltiaHeABXz2ph5f7wHsC9cEqXjr4Tt+sXu9tURKMq
            hGNNYFgJPIsa0q07dqClJtNxS0hCkCp4gEFjsCVLFPzxEP+TU8OND7eNgXqQ9TYG
            zQGNEVN2Dmk/HFatTRnKY2wqlYjfFXhUsubVSPm0krIU04JeBgqo/B7u20G3wwW/
            EWhA8skCgYEA73gkpHxKnykzJBx3jbPNgcegBJA2cqv7IonOO+KG1nqccnOzzYZX
            DFrEqemVuESPUSz1dzvilKkb2Fz+t8PFg9Qq4nV2Oa7h5TYp05T6dyuwrcmoPiIM
            9kT7YGohaucf9EqRIYkjMbefWn9reiXKOztemD8Nq40GqT96zWdll+0CgYEA42DC
            vHnNS3ChPN6ueiiGrSYNiu0o35/+Zv0/YAXF69gC118qtBof8lVr74/vSE3SqNyh
            /8y8WhM/TlErZSSKoUZCIkQE3LhIsbR0Nh95RwY0It/jbnVTwb11/PkILfvaQlwQ
            8DM2WXYg39QdPlYw1GNTvKuAYtzeROUqOoF5BRsCgYEA3qDTcBgdR9sFsIzGmPaQ
            GBd+rL9l3zYERBfZo9L1iHB1AfKPNoOuac35B/4hMy6KDu29Rxxlic+uE3hhVnar
            KeQV+nM5dmcfm/i+6fWW5TO5DdhskVcWtd1r1jbU2o4FJxgr1QGpto7/lyLeyLBZ
            UrffOatlChgSGUbq5As8aAECgYAogmivY5PryNkxGwtCwE2eM5VeFvqdPMf6WUwd
            M2obppR7An19MNpYNlfQing7DYJmi0hhZnx4H827ikKM9oGsUfQeXrfvCvYIkvnR
            WrIksTpArFq8pzKQ5cxLkaKfbqtn/zcVVEpujdk1h3jeTkTM0hVtG7D37Bm9dIad
            fcut2QKBgGwhl9lil+kDVkmWajQGHzxrct1hWlcn8hsXcO6bu8TGSYTjeT0XQUog
            OjdB5pTbPXncE/3ExaMttiBV8eLkhW+HRXq+IxyWPG3ROu5N1tTxBtV7X5tkzY9m
            V5rUvEN+bLOUGLGA4qd66j5DC0QwP1gaAHlpnMoipNvgXmEcriSu
            -----END RSA PRIVATE KEY-----
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

        using PemReader reader = new(new StreamReader(new MemoryStream(rsa2048PrivateKey.ToArray())));
        AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)reader.ReadObject();
        RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

        Span<byte> p = stackalloc byte[privateKey.P.GetLengthofByteArray()];
        privateKey.P.ToByteArray(p);
        Span<byte> q = stackalloc byte[privateKey.Q.GetLengthofByteArray()];
        privateKey.Q.ToByteArray(q);

        Capabilities capabilities = Capabilities.From("sign-pss"u8);
        Domains domainFive = Domains.From("5"u8);
        ObjectId keyId = session.ImportRsaKey(keyLabel, domainFive, in capabilities, Algorithm.Rsa2048, p, q);
        output.WriteLine($"Key imported with ID {keyId}.");

        output.WriteLine($"Data to sign ({data.Length} bytes) is: {Encoding.UTF8.GetString(data)}");
        Span<byte> hashedData = stackalloc byte[32];
        IDigest sha256 = DigestUtilities.GetDigest("SHA256");
        sha256.BlockUpdate(data);
        int written = sha256.DoFinal(hashedData);
        hashedData = hashedData[..written];
        output.WriteLine($"Hash of data ({hashedData.Length} bytes) is: {Convert.ToHexString(hashedData)}");

        Span<byte> signature = stackalloc byte[512];
        written = session.SignPss(keyId, data, signature, saltLength: 32, Algorithm.Mgf1Sha256);
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