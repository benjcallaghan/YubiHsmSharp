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
using System.Threading;

namespace YubiHsmSharp;

internal partial class DebugFile : IDisposable
{
    [LibraryImport("ucrtbase.dll", EntryPoint = "_open_osfhandle", SetLastError = false)]
    private static partial int win_open_osfhandle(nint osfhandle, int flags);

    [LibraryImport("ucrtbase.dll", EntryPoint = "_fdopen", SetLastError = true)]
    private static partial nint win_fdopen(int fd, ReadOnlySpan<byte> mode);

    [LibraryImport("ucrtbase.dll", EntryPoint = "_fclose_nolock", SetLastError = true)]
    private static partial int win_fclose(nint stream);

    [LibraryImport("libc", EntryPoint = "fdopen", SetLastError = true)]
    private static partial nint posix_fdopen(int filedes, ReadOnlySpan<byte> mode);

    [LibraryImport("libc", EntryPoint = "fclose", SetLastError = true)]
    private static partial int posix_fclose(nint stream);

    private readonly AnonymousPipeServerStream server;
    private bool disposed;

    public nint WriteFile { get; }
    public Stream ReadStream => this.server;

    public DebugFile()
    {
        this.server = new(PipeDirection.In, HandleInheritability.None, 4096);
        nint clientHandle = this.server.ClientSafePipeHandle.DangerousGetHandle();

        this.WriteFile = OpenFileStream(clientHandle);

        if (this.WriteFile is 0)
        {
            this.server.Dispose();
            throw new Win32Exception(); // Automatically captures LastError from fdopen.
        }

        this.server.DisposeLocalCopyOfClientHandle();
    }

    private static nint OpenFileStream(nint clientHandle)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Convert handle to a file descriptor, then convert that to a FILE* stream.
            int fd = win_open_osfhandle((int)clientHandle, 0);
            return fd is -1 ? 0 : win_fdopen(fd, "w"u8);
        }
        else
        {
            // The handle is already a file descriptor, so just convert that to a FILE* stream.
            return posix_fdopen((int)clientHandle, "w"u8);
        }
    }

    private static void CloseFileStream(nint stream)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            win_fclose(stream);
        }
        else
        {
            posix_fclose(stream);
        }
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!this.disposed)
        {
            CloseFileStream(this.WriteFile);

            if (disposing)
            {
                this.server.Dispose();
            }
            this.disposed = true;
        }
    }

    ~DebugFile()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}

internal class Arc<T> : IDisposable where T : IDisposable
{
    private class SharedState(T resource)
    {
#if NET9_0_OR_GREATER
        public readonly Lock Lock = new();
#else
        public readonly object Lock = new();
#endif
        public readonly T Resource = resource;
        public int RefCount = 1;
        public bool IsCurrent = true;
    }

    private readonly SharedState state;
    private bool disposed = false;

    public T Value => this.state.Resource;

    public bool IsCurrent
    {
        get { lock (this.state.Lock) return this.state.IsCurrent; }
        set { lock (this.state.Lock) this.state.IsCurrent = value; }
    }

    public Arc(T resource)
    {
        this.state = new SharedState(resource);
    }

    private Arc(SharedState state)
    {
        this.state = state;
        lock (this.state.Lock)
        {
            this.state.RefCount++;
        }
    }

    public Arc<T> Clone()
    {
        lock (this.state.Lock)
        {
            if (this.state.RefCount <= 0)
            {
                throw new ObjectDisposedException(nameof(Arc<T>));
            }
            return new Arc<T>(this.state);
        }
    }

    public void Dispose()
    {
        if (this.disposed) return;

        bool shouldDisposeResource = false;

        lock (this.state.Lock)
        {
            this.state.RefCount--;
            if (this.state.RefCount == 0 && !this.state.IsCurrent)
            {
                shouldDisposeResource = true;
            }
        }

        if (shouldDisposeResource)
        {
            this.state.Resource.Dispose();
        }

        this.disposed = true;
    }
}