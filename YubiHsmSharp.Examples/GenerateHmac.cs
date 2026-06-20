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

using Xunit.Abstractions;

namespace YubiHsmSharp.Examples;

[Trait("Requires", "YubiHSM")]
public class GenerateHmac(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> keyLabel = "label"u8;
        ReadOnlySpan<byte> password = "password"u8;
        ReadOnlySpan<byte> data = "sudo make me a sandwich"u8;
        ObjectId authKeyId = new(1);

        using YubiModule module = YubiModule.Instance;
        using YubiConnector connector = module.InitConnector(ConnectorUrl.Utf8Value);
        connector.Connect();
        using YubiSession session = connector.CreateSession(authKeyId, password);

        byte sessionId = session.SessionId;
        output.WriteLine($"Successfully established session {sessionId} using Authentication Key {authKeyId}.");

        Capabilities capabilities = Capabilities.From("sign-hmac:verify-hmac"u8);
        Domains domainFive = Domains.From("5"u8);
        ObjectId keyId = session.GenerateHmacKey(keyLabel, domainFive, in capabilities, Algorithm.HmacSha256);
        output.WriteLine($"Generated HMAC-SHA256 key with ID {keyId}.");

        Span<byte> hmacData = stackalloc byte[64];
        int written = session.SignHmac(keyId, data, hmacData);
        hmacData = hmacData[..written];
        output.WriteLine($"HMAC of data ({hmacData.Length} bytes) is: {Convert.ToHexString(hmacData)}");

        bool verified = session.VerifyHmac(keyId, hmacData, data);
        Assert.True(verified);
        output.WriteLine($"Successfully verified HMAC.");

        hmacData[0] += 1;
        verified = session.VerifyHmac(keyId, hmacData, data);
        Assert.False(verified);
        output.WriteLine($"Unable to verify HMAC.");
    }
}