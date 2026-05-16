using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using YubiHsmSharp;

public static class Initializer
{
    [ModuleInitializer]
    public static void Initialize()
    {
        NativeLibrary.SetDllImportResolver(typeof(YubiModule).Assembly, ResolveDll);
    }

    private static nint ResolveDll(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName == "yubihsm")
        {
            return NativeLibrary.Load(@"C:\Program Files\Yubico\YubiHSM Shell\bin\libyubihsm.dll");
        }

        return IntPtr.Zero;
    }
}