using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

namespace YubiHsmSharp;

internal partial class DebugFile
{
    private const int O_BINARY = 0x8000;
    private const int O_NOINHERIT = 0x0080;

    [LibraryImport("ucrtbase.dll", EntryPoint = "_pipe", SetLastError = true)]
    private static partial int win_pipe(Span<int> pfds, uint psize, int textmode);

    [LibraryImport("libc", EntryPoint = "pipe", SetLastError = true)]
    private static partial int posix_pipe(Span<int> pipefd);

    public static DebugFile Create()
    {
        // FIXME: In .NET 11, much of this can be replaced with SafeFileHandle.CreateAnonymousPipe()
        Span<int> fds = stackalloc int[2];

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            int rc = win_pipe(fds, 4096, O_BINARY | O_NOINHERIT);
            ThrowIfError(rc);
        }
        else
        {
            int rc = posix_pipe(fds);
            ThrowIfError(rc);
        }

        SafeFileHandle readFD = new(fds[0], ownsHandle: true);
        SafeFileHandle writeFD = new(fds[1], ownsHandle: true);
    }

    private static void ThrowIfError(int rc)
    {
        if (rc != 0)
        {
            // Win32Exception properly handles errno/GetLastPInvokeError, even on non-Windows systems.
            throw new Win32Exception();
        }
    }
}