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

public class Info(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        using YubiModule module = YubiModule.Instance;
        using YubiConnector connector = module.InitConnector(ConnectorUrl.Utf8Value);
        connector.Connect();

        ReadOnlySpan<byte> receivedUrl = connector.Utf8Address;
        Assert.True(connector.HasDevice);
        output.WriteLine($"Successfully connected to {Encoding.UTF8.GetString(receivedUrl)}, device is present.");

        (byte major, byte minor, byte patch) = connector.Version;
        output.WriteLine($"Connector Version: {major}.{minor}.{patch}");

        DeviceInfo info = connector.GetDeviceInfo();
        output.WriteLine($"Device Version: {info.Major}.{info.Minor}.{info.Patch}");
        output.WriteLine($"Serial: {info.Serial}");
        output.WriteLine($"Log: {info.LogUsed}/{info.LogTotal} (used/total)");
        output.WriteLine("Supported algorithms:");
        foreach (Algorithm algorithm in info.Algorithms)
        {
            output.WriteLine($"\t{algorithm.ToYubiString()}");
        }
    }
}