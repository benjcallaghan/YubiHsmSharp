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

namespace YubiHsmSharp.Tests;

public class AsymmetricAuthentication
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
        if (device.Algorithms.Contains(Algorithm.ECP256YubicoAuthentication))
        {
            return; // Device does not support asymmetric authentication.
        }

        ReadOnlySpan<byte> requestData = "sudo make me a sandwich"u8;
        Span<byte> responseData = stackalloc byte[requestData.Length];
        (Command response, int responseLength) = connector.SendMessage(Command.Echo, requestData, responseData);
        responseData = responseData[..responseLength];

        Span<byte> clientPrivateKey = stackalloc byte[32];
        Span<byte> clientPublicKey = stackalloc byte[65];
        ushort authKeyId = 1;

        using (YubiSession session = connector.CreateSession(authKeyId, "password"u8))
        {
            authKeyId = 2;
            try
            {
                session.DeleteObject(authKeyId, ObjectType.AuthenticationKey);
            }
            catch
            {
                // Ignoring result
            }

            module.GenerateECP256Key(clientPrivateKey, clientPublicKey);

            Capabilities caps = Capabilities.From("change-authentication-key,get-pseudo-random"u8);

            authKeyId = session.ImportAuthenticationKey("EC Auth Key"u8, new Domains(0xffff), caps, caps,
                clientPublicKey[1..], [], authKeyId);
        }

        Span<byte> devicePublicKey = stackalloc byte[65];
        (Algorithm algorithm, int written) = connector.GetDevicePublicKey(devicePublicKey);
        devicePublicKey = devicePublicKey[..written];

        Span<byte> buffer = stackalloc byte[32];

        using (YubiSession session = connector.CreateSessionAsymmetric(authKeyId, clientPrivateKey, devicePublicKey))
        {
            byte sessionId = session.SessionId;

            session.GetPseudoRandom(buffer);

            Span<byte> response2Data = stackalloc byte[requestData.Length];
            (Command response2, int response2Length) = session.SendMessage(Command.Echo, requestData, response2Data);
            response2Data = response2Data[..response2Length];
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