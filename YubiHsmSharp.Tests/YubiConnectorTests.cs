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

public class YubiConnectorTests
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

        Span<byte> requestData = stackalloc byte[length];
        requestData.Fill(0x0f);

        // Act
        Span<byte> responseData = stackalloc byte[3136];
        (Command response, int written) = connector.SendMessage(Command.Echo, requestData, responseData);
        responseData = responseData[..written];

        // Assert
        Assert.Equal(requestData, responseData);
    }
}