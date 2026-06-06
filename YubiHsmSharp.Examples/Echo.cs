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

public class Echo(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> password = "password"u8;
        ReadOnlySpan<byte> data = "sudo make me a sandwich"u8;

        using YubiModule module = new();
        using YubiConnector connector = module.InitConnector("http://localhost:12345"u8);
        connector.Connect();

        ReadOnlySpan<byte> receivedUrl = connector.Utf8Address;
        connector.SetVerbosity(Verbosity.All);

        output.WriteLine("Send a plain (unencrypted, unauthenticated) echo command.");
        Span<byte> responseData = stackalloc byte[data.Length];
        (Command response, int written) = connector.SendMessage(Command.Echo, data, responseData);
        responseData = responseData[..written];
        output.WriteLine($"Response ({responseData.Length} bytes): {Encoding.UTF8.GetString(responseData)}");

        ObjectId authKeyId = new(1);
        using YubiSession session = connector.CreateSession(authKeyId, password);

        byte sessionId = session.SessionId;
        output.WriteLine($"Successfully established session {sessionId}.");

        output.WriteLine("Send a secure echo command.");
        Span<byte> response2Data = stackalloc byte[data.Length];
        (Command response2, written) = session.SendMessage(Command.Echo, data, response2Data);
        response2Data = response2Data[..written];
        output.WriteLine($"Response ({response2Data.Length} bytes): {Encoding.UTF8.GetString(response2Data)}");

        Assert.Equal(responseData, response2Data);
    }
}