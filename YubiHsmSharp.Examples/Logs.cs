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

public class Logs(ITestOutputHelper output)
{
    [Fact]
    public void Main()
    {
        ReadOnlySpan<byte> password = "password"u8;
        ObjectId authKeyId = new(1);

        using YubiModule module = YubiModule.Instance;
        using YubiConnector connector = module.InitConnector(ConnectorUrl.Utf8Value);
        connector.Connect();
        using YubiSession session = connector.CreateSession(authKeyId, password);

        byte sessionId = session.SessionId;
        output.WriteLine($"Successfully established session {sessionId}.");

        session.CommandAudit[Command.SetOption] = DeviceOption.Enabled;
        session.CommandAudit[Command.SetLogIndex] = DeviceOption.Enabled;
        session.CommandAudit[Command.GetObjectInfo] = DeviceOption.Enabled;

        output.WriteLine("Flushing existing logs.");
        Span<LogEntry> logs = stackalloc LogEntry[64]; // Max log entries
        (ushort unloggedBoot, ushort unloggedAuth, int written) = session.GetLogEntries(logs);

        LogEntry? lastPreviousLog = written > 0 ? logs[written - 1] : null;
        if (lastPreviousLog is not null)
        {
            session.SetLogIndex(lastPreviousLog.Value.Number);
        }

        output.WriteLine("Performing some operations.");
        const int operations = 8;
        for (int i = 0; i < operations; i++)
        {
            _ = session.GetObject(authKeyId, ObjectType.AuthenticationKey);
        }

        output.WriteLine("Getting logs.");
        (unloggedBoot, unloggedAuth, written) = session.GetLogEntries(logs);
        Assert.Equal(operations + 1, written); // N calls to GetObject and 1 call to SetLogIndex.
        logs = logs[..written];

        output.WriteLine($"{unloggedBoot} unlogged boots found.");
        output.WriteLine($"{unloggedAuth} unlogged authentications found.");
        output.WriteLine($"Found {logs.Length} items.");

        foreach (LogEntry entry in logs)
        {
            output.WriteLine($"item: {entry.Number} -- cmd: {entry.Command} -- length: {entry.Length} -- session key: {entry.SessionKey} -- target key: {entry.TargetKey} -- second key: {entry.SecondKey} -- result: {entry.Result} -- tick: {entry.Systick} -- hash: {Convert.ToHexString(entry.Digest)}");
        }

        bool verified = LogEntry.Verify(logs, in lastPreviousLog);
        Assert.True(verified);
        output.WriteLine("Logs correctly verified.");

        session.CommandAudit[Command.SetOption] = DeviceOption.Disabled;
        Assert.Equal(DeviceOption.Disabled, session.CommandAudit[Command.SetOption]);

        session.CommandAudit[Command.SetOption] = DeviceOption.Enabled;
        Assert.Equal(DeviceOption.Enabled, session.CommandAudit[Command.SetOption]);
    }
}