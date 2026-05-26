using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

namespace YubiHsmSharp;

internal partial class DebugFile : IDisposable
{
    private const int WIN_BINARY = 0x8000;
    private const int WIN_NOINHERIT = 0x0080;
    private const int WIN_IOLBF = 0x0040;
    private const int POSIX_IOLBF = 0x0001;

    [LibraryImport("ucrtbase.dll", EntryPoint = "_pipe", SetLastError = true)]
    private static partial int win_pipe(Span<int> pfds, uint psize, int textmode);

    [LibraryImport("ucrtbase.dll", EntryPoint = "_fdopen", SetLastError = true)]
    private static partial nint win_fdopen(int fd, ReadOnlySpan<byte> mode);

    [LibraryImport("ucrtbase.dll", EntryPoint = "setvbuf", SetLastError = true)]
    private static partial int win_setvbuf(nint stream, nint buffer, int mode, nuint size);

    [LibraryImport("libc", EntryPoint = "pipe", SetLastError = true)]
    private static partial int posix_pipe(Span<int> pipefd);

    [LibraryImport("libc", EntryPoint = "fdopen", SetLastError = true)]
    private static partial nint posix_fdopen(int filedes, ReadOnlySpan<byte> mode);

    [LibraryImport("libc", EntryPoint = "setvbuf", SetLastError = true)]
    private static partial int posix_setvbuf(nint stream, nint buf, int type, nuint size);

    private readonly SafeFileHandle readHandle;
    private readonly SafeFileHandle writeHandle;
    private readonly nint writeFile;
    private readonly FileStream readStream;

    public DebugFile()
    {
        // FIXME: In .NET 11, much of this can be replaced with SafeFileHandle.CreateAnonymousPipe()
        Span<int> fds = stackalloc int[2];
        const int bufferSize = 4096;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            int rc = win_pipe(fds, bufferSize, WIN_BINARY | WIN_NOINHERIT);
            ThrowIfError(rc);

            this.readHandle = new(fds[0], ownsHandle: true);
            this.writeHandle = new(fds[1], ownsHandle: true);

            this.writeFile = win_fdopen((int)this.writeHandle.DangerousGetHandle(), "w"u8);
            ThrowIfNull(this.writeFile);

            rc = win_setvbuf(this.writeFile, 0, WIN_IOLBF, bufferSize);
            ThrowIfError(rc);
        }
        else
        {
            int rc = posix_pipe(fds);
            ThrowIfError(rc);

            this.readHandle = new(fds[0], ownsHandle: true);
            this.writeHandle = new(fds[1], ownsHandle: true);

            this.writeFile = posix_fdopen((int)this.writeHandle.DangerousGetHandle(), "w"u8);
            ThrowIfNull(this.writeFile);

            rc = posix_setvbuf(this.writeFile, 0, POSIX_IOLBF, bufferSize);
            ThrowIfError(rc);
        }

        this.readStream = new FileStream(this.readHandle, FileAccess.Read, bufferSize, isAsync: false);
    }

    public void Dispose()
    {
        this.readHandle.Dispose();
        this.writeHandle.Dispose();
    }

    private static void ThrowIfError(int rc)
    {
        if (rc != 0)
        {
            // Win32Exception properly handles errno/GetLastPInvokeError, even on non-Windows systems.
            throw new Win32Exception();
        }
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