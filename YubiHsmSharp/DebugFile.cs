/*
 * Copyright 2026 Benjamin Callaghan
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

using System.ComponentModel;
using System.IO.Pipes;

namespace YubiHsmSharp;

internal partial class DebugFile : IDisposable
{
    [LibraryImport("ucrtbase.dll", EntryPoint = "_open_osfhandle", SetLastError = false)]
    private static partial int win_open_osfhandle(nint osfhandle, int flags);

    [LibraryImport("ucrtbase.dll", EntryPoint = "_fdopen", SetLastError = true)]
    private static partial nint win_fdopen(int fd, ReadOnlySpan<byte> mode);

    [LibraryImport("libc", EntryPoint = "fdopen", SetLastError = true)]
    private static partial nint posix_fdopen(int filedes, ReadOnlySpan<byte> mode);

    private readonly AnonymousPipeServerStream server;

    public nint WriteFile { get; }
    public Stream ReadStream => this.server;

    public DebugFile()
    {
        this.server = new(PipeDirection.In, HandleInheritability.None, 4096);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var fd = win_open_osfhandle((int)this.server.ClientSafePipeHandle.DangerousGetHandle(), 0);
            this.WriteFile = win_fdopen(fd, "w"u8);
        }
        else
        {
            this.WriteFile = posix_fdopen((int)this.server.ClientSafePipeHandle.DangerousGetHandle(), "w"u8);
        }

        ThrowIfNull(this.WriteFile);
    }

    public void Dispose()
    {
        this.server.Dispose();
    }

    private static void ThrowIfNull(nint ptr)
    {
        if (ptr == 0)
        {
            // Win32Exception properly handles errno/GetLastPInvokeError, even on non-Windows systems.
            throw new Win32Exception();
        }
    }
}