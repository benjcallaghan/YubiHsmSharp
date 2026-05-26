using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

namespace YubiHsmSharp;

internal partial class DebugFile
{
    private const int O_BINARY = 0x8000;
    private const int O_NOINHERIT = 0x0080;

    [LibraryImport("ucrtbase.dll", EntryPoint = "_pipe", SetLastError = true)]
    private static partial int win_pipe(Span<int> pfds, uint psize, int textmode);

    [LibraryImport("ucrtbase.dll", EntryPoint = "_fdopen", SetLastError = true)]
    private static partial nint win_fdopen(int fd, ReadOnlySpan<byte> mode);

    [LibraryImport("libc", EntryPoint = "pipe", SetLastError = true)]
    private static partial int posix_pipe(Span<int> pipefd);

    [LibraryImport("libc", EntryPoint = "fdopen", SetLastError = true)]
    private static partial nint posix_fdopen(int filedes, ReadOnlySpan<byte> mode);

    public static DebugFile Create()
    {
        // FIXME: In .NET 11, much of this can be replaced with SafeFileHandle.CreateAnonymousPipe()
        Span<int> fds = stackalloc int[2];

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            int rc = win_pipe(fds, 4096, O_BINARY | O_NOINHERIT);
            ThrowIfError(rc);

            SafeFileHandle readFD = new(fds[0], ownsHandle: true);
            SafeFileHandle writeFD = new(fds[1], ownsHandle: true);

            nint file = win_fdopen((int)writeFD.DangerousGetHandle(), "w"u8);
            ThrowIfNull(file);
        }
        else
        {
            int rc = posix_pipe(fds);
            ThrowIfError(rc);

            SafeFileHandle readFD = new(fds[0], ownsHandle: true);
            SafeFileHandle writeFD = new(fds[1], ownsHandle: true);

            nint file = posix_fdopen((int)writeFD.DangerousGetHandle(), "w"u8);
            ThrowIfNull(file);
        }
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