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

public class WrapData(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> keyLabel = "label"u8;
        ReadOnlySpan<byte> password = "password"u8;
        ReadOnlySpan<byte> clear = "test data"u8;
        ObjectId authKeyId = new(1);

        using YubiModule module = YubiModule.Instance;
        using YubiConnector connector = module.InitConnector("http://localhost:12345"u8);
        connector.Connect();
        using YubiSession session = connector.CreateSession(authKeyId, password);

        byte sessionId = session.SessionId;
        output.WriteLine($"Successfully established session {sessionId}.");

        Capabilities capabilities = Capabilities.From("wrap-data:unwrap-data"u8);
        Capabilities delegatedCapabilities = new();
        Domains domainFive = Domains.From("5"u8);
        ObjectId wrappingKeyId = session.GenerateWrapKey(keyLabel, domainFive, in capabilities, Algorithm.Aes256CcmWrap, in delegatedCapabilities);
        output.WriteLine($"Generated wrapping key with ID {wrappingKeyId}.");

        Span<byte> data = stackalloc byte[1024];
        int dataLength = session.WrapData(wrappingKeyId, clear, data);
        output.WriteLine($"Data wrapped to length {dataLength}.");

        Assert.Equal(clear.Length + 30, dataLength); // Length includes CCM Wrap Overhead.
        Assert.False(clear.SequenceEqual(data[..dataLength]));

        dataLength = session.UnwrapData(wrappingKeyId, data[..dataLength], data);
        Assert.Equal(clear, data[..dataLength]);
        output.WriteLine("Data unwrapped successfully.");
    }
}