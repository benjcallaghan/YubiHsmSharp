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

public class YubiSessionTests
{
    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(512)]
    [InlineData(1024)]
    public void SendCommand_WithEchoRequest_ShouldReturnEqualResponse(int length)
    {
        // Arrange
        using YubiModule module = YubiModule.Instance;
        YubiConnector.Verbosity = Verbosity.Quiet;
        using YubiConnector connector = module.InitConnector(ConnectorUrl.Utf8Value);
        connector.Connect();

        Span<byte> key = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f];
        using YubiSession session = connector.CreateSession(new(0), key, key, recreateSession: false);

        Span<byte> requestData = stackalloc byte[length];
        requestData.Fill(0x0f);

        // Act
        Span<byte> responseData = stackalloc byte[3136];
        (Command response, int written) = session.SendMessage(Command.Echo, requestData, responseData);
        responseData = responseData[..written];

        // Assert
        Assert.Equal(requestData, responseData);
    }
}