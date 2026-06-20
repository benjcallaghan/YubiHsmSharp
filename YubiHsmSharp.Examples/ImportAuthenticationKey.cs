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
public class ImportAuthenticationKey(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> keyLabel = "label"u8;
        ReadOnlySpan<byte> password1 = "password"u8;
        ReadOnlySpan<byte> password2 = "letmein!"u8;
        ObjectId authKeyId = new(1);

        using YubiModule module = YubiModule.Instance;
        using YubiConnector connector = module.InitConnector(ConnectorUrl.Utf8Value);
        connector.Connect();

        byte sessionId;
        ObjectId keyId;
        using (YubiSession session = connector.CreateSession(authKeyId, password1))
        {
            sessionId = session.SessionId;
            output.WriteLine($"Successfully established session {sessionId} using Authentication Key {authKeyId}.");

            Capabilities capabilities = Capabilities.From("get-log-entries"u8);
            Domains domainFive = Domains.From("5"u8);
            keyId = session.ImportAuthenticationKey(keyLabel, domainFive, in capabilities, in capabilities, password2);
            output.WriteLine($"Imported Authentication Key with ID {keyId}.");
        }
        output.WriteLine($"Closed session {sessionId}.");

        using (YubiSession session = connector.CreateSession(keyId, password2))
        {
            sessionId = session.SessionId;
            output.WriteLine($"Successfully established session {sessionId} using Authentication Key {keyId}.");

            output.WriteLine("Trying to get log entries.");
            Span<LogEntry> logs = stackalloc LogEntry[64]; // Maximum number of log entries.
            (ushort unloggedBoot, ushort unloggedAuth, int written) = session.GetLogEntries(logs);
            output.WriteLine($"Got {written} log entries.");

            output.WriteLine($"Trying to get 16 bytes of random data.");
            Action getRandom = () =>
            {
                Span<byte> data = stackalloc byte[16];
                _ = session.GetPseudoRandom(data);
            };
            YubiHsmException ex = Assert.Throws<YubiHsmException>(getRandom);
            output.WriteLine($"Unable to get random data: {ex.Message}");
        }
    }
}