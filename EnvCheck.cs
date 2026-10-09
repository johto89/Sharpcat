using System;
using System.Threading;

namespace SvcUtil
{
    internal static class Env
    {
        /// <summary>
        /// Run all environment checks.
        /// </summary>
        public static bool Go()
        {
            return C1()
                && C2()
                && C3()
                && C4()
                && C5();
        }

        /// <summary>
        /// Verify timing consistency.
        /// </summary>
        public static bool C1()
        {
            ulong t1 = W.MH();
            Thread.Sleep(2000);
            ulong t2 = W.MH();
            return (t2 - t1) >= 1900;
        }

        /// <summary>
        /// Check NUMA allocation support.
        /// </summary>
        public static bool C2()
        {
            IntPtr result = W.ME(
                W.M6(),
                IntPtr.Zero,
                (UIntPtr)0x1000,         // 4 KB
                0x3000,                  // MEM_COMMIT | MEM_RESERVE
                0x04,                    // PAGE_READWRITE
                0);                      // NUMA node 0

            if (result == IntPtr.Zero)
                return false;

            // Clean up the test allocation
            W.MD(result, UIntPtr.Zero, 0x8000); // MEM_RELEASE
            return true;
        }

        /// <summary>
        /// Check FLS support.
        /// </summary>
        public static bool C3()
        {
            uint idx = W.MF(IntPtr.Zero);
            if (idx == 0xFFFFFFFF) // FLS_OUT_OF_INDEXES
                return false;

            W.MG(idx);
            return true;
        }

        /// <summary>
        /// Check processor count.
        /// </summary>
        public static bool C4()
        {
            return Environment.ProcessorCount >= 2;
        }

        /// <summary>
        /// Check system uptime.
        /// </summary>
        public static bool C5()
        {
            ulong uptime = W.MH();
            return uptime > 600000; // 10 minutes in milliseconds
        }
    }
}
