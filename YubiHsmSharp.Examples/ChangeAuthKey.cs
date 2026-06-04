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
using Xunit.Abstractions;

namespace YubiHsmSharp.Examples;

 public class ChangeAuthKey(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> keyLabel = "label"u8;
        ReadOnlySpan<byte> password1 = "password"u8;
        ReadOnlySpan<byte> password2 = "letmein!"u8;
        ReadOnlySpan<byte> password3 = "PASSWORD"u8;
        ushort authKey = 1;

        using YubiModule module = new();
        using YubiConnector connector = module.InitConnector("http://localhost:12345"u8);
        connector.Connect();

        byte sessionId;
        ushort keyId;
        using (YubiSession session = connector.CreateSession(authKey, password1))
        {
            sessionId = session.SessionId;
            output.WriteLine($"Successfully established session {sessionId} using Authentication Key {authKey}");

            Capabilities capabilities = Capabilities.From("change-authentication-key"u8);
            Domains domainFive = Domains.From("5"u8);
            keyId = session.ImportAuthenticationKey(keyLabel, domainFive, in capabilities, in capabilities, password2);
            output.WriteLine($"Imported Authentication Key with ID {keyId} and password {Encoding.UTF8.GetString(password2)}");

            // ChangeAuthenticationKey can only be used to modify the key that created `session`.
            Action changeKey = () => session.ChangeAuthenticationKey(keyId, "PASSWORD"u8);
            Assert.Throws<YubiHsmException>(changeKey);
            output.WriteLine($"Unable to change Authentication Key with ID {keyId} from this session.");
        }
        output.WriteLine($"Closed session {sessionId}.");

        using (YubiSession session = connector.CreateSession(keyId, password2))
        {
            sessionId = session.SessionId;
            output.WriteLine($"Successfully established session {sessionId} using Authentication Key {keyId}.");

            keyId = session.ChangeAuthenticationKey(keyId, password3);
            output.WriteLine($"Successfully changed Authentication Key with ID {keyId} to password {Encoding.UTF8.GetString(password3)}");
        }
        output.WriteLine($"Closed session {sessionId}.");

        Action openSession = () => connector.CreateSession(keyId, "letmein!"u8);
        Assert.Throws<YubiHsmException>(openSession);
        output.WriteLine($"Unable to open session with Authentication Key {keyId} and password {Encoding.UTF8.GetString(password2)}.");

        using (YubiSession session = connector.CreateSession(keyId, password3))
        {
            sessionId = session.SessionId;
            output.WriteLine($"Successfully established session {sessionId} using Authentication Key {keyId} and password {Encoding.UTF8.GetString(password3)}.");
        }
    }
}