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

public class AsymmetricAuthentication(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        using YubiModule module = new();
        using YubiConnector connector = module.InitConnector("http://localhost:12345"u8);
        connector.Connect();

        var receivedUrl = connector.Utf8Address;

        connector.SetVerbosity(Verbosity.All);

        DeviceInfo device = connector.GetDeviceInfo();
        if (!device.Algorithms.Contains(Algorithm.ECP256YubicoAuthentication))
        {
            output.WriteLine("Skipping this test because the device does not support asymmetric authentication.");
            return;
        }

        output.WriteLine("Send a plain (unencrypted, unauthenticated) echo command.");
        ReadOnlySpan<byte> requestData = "sudo make me a sandwich"u8;
        Span<byte> responseData = stackalloc byte[requestData.Length];
        (Command response, int responseLength) = connector.SendMessage(Command.Echo, requestData, responseData);
        responseData = responseData[..responseLength];

        Span<byte> clientPrivateKey = stackalloc byte[32];
        Span<byte> clientPublicKey = stackalloc byte[65];
        ObjectId authKeyId = new(1);

        // By default, the HSM does not contain any asymmetric authentication keys.
        using (YubiSession session = connector.CreateSession(authKeyId, "password"u8))
        {
            authKeyId = new(2);
            try
            {
                session.DeleteObject(authKeyId, ObjectType.AuthenticationKey);
            }
            catch
            {
                // Ignoring "not found" error; ensures auth key 2 does not exist.
            }

            module.GenerateECP256Key(clientPrivateKey, clientPublicKey);

            Capabilities caps = Capabilities.From("change-authentication-key,get-pseudo-random"u8);

            // The first byte of an EC public key is the "uncompressed" marker 0x04, which should not be included during import.
            authKeyId = session.ImportAuthenticationKey("EC Auth Key"u8, new Domains(0xffff), in caps, in caps,
                clientPublicKey[1..], [], authKeyId);
        }

        Span<byte> devicePublicKey = stackalloc byte[65];
        (Algorithm algorithm, int written) = connector.GetDevicePublicKey(devicePublicKey);
        devicePublicKey = devicePublicKey[..written];

        Span<byte> buffer = stackalloc byte[32];

        using (YubiSession session = connector.CreateSessionAsymmetric(authKeyId, clientPrivateKey, devicePublicKey))
        {
            byte sessionId = session.SessionId;
            output.WriteLine($"Successfully established session {sessionId}.");

            session.GetPseudoRandom(buffer);

            output.WriteLine("Send a secure echo command.");
            Span<byte> response2Data = stackalloc byte[requestData.Length];
            (Command response2, int response2Length) = session.SendMessage(Command.Echo, requestData, response2Data);
            response2Data = response2Data[..response2Length];
            output.WriteLine($"Response ({response2Length} bytes): {Encoding.UTF8.GetString(response2Data)}");
            Assert.Equal(responseData, response2Data);

            module.GenerateECP256Key(clientPrivateKey, clientPublicKey);

            session.ChangeAuthenticationKey(authKeyId, clientPublicKey[1..], []);
        }

        using (YubiSession session = connector.CreateSessionAsymmetric(authKeyId, clientPrivateKey, devicePublicKey))
        {
            session.GetPseudoRandom(buffer);
        }
    }
}