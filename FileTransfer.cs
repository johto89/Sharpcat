using System;
using System.IO;
using System.Text;

namespace SvcUtil
{
    internal static class FileTransfer
    {
        private const string UploadCmd = "!upload ";
        private const string DownloadCmd = "!download ";

        /// <summary>
        /// Check if a line is a file transfer command. Returns true if handled.
        /// </summary>
        public static bool TryHandle(string line, IShellStream stream)
        {
            line = line.Trim();

            if (line.StartsWith(UploadCmd, StringComparison.OrdinalIgnoreCase))
                return HandleUpload(line.Substring(UploadCmd.Length).Trim(), stream);

            if (line.StartsWith(DownloadCmd, StringComparison.OrdinalIgnoreCase))
                return HandleDownload(line.Substring(DownloadCmd.Length).Trim(), stream);

            return false;
        }

        /// <summary>
        /// Receive a file from the remote end and save locally.
        /// Expected from remote: "SIZE n\n" followed by n bytes.
        /// </summary>
        private static bool HandleUpload(string args, IShellStream stream)
        {
            // Parse "path size"
            int lastSpace = args.LastIndexOf(' ');
            if (lastSpace < 0)
            {
                SendLine(stream, "ERR: usage: !upload <path> <size>");
                return true;
            }

            string path = args.Substring(0, lastSpace).Trim();
            string sizeStr = args.Substring(lastSpace + 1).Trim();

            long size;
            if (!long.TryParse(sizeStr, out size) || size < 0)
            {
                SendLine(stream, "ERR: invalid size");
                return true;
            }

            try
            {
                using (var fs = new FileStream(path, FileMode.Create,
                                               FileAccess.Write))
                {
                    byte[] buf = new byte[Config.BufferSize];
                    long remaining = size;

                    while (remaining > 0)
                    {
                        int toRead = (int)Math.Min(remaining, buf.Length);
                        int got = stream.Receive(buf, 0, toRead);
                        if (got <= 0)
                        {
                            SendLine(stream, "ERR: connection lost during upload");
                            return true;
                        }
                        fs.Write(buf, 0, got);
                        remaining -= got;
                    }
                }

                SendLine(stream, "OK: saved " + size + " bytes to " + path);
            }
            catch (Exception ex)
            {
                SendLine(stream, "ERR: " + ex.Message);
            }

            return true;
        }

        private static bool HandleDownload(string path, IShellStream stream)
        {
            path = path.Trim();

            if (!File.Exists(path))
            {
                SendLine(stream, "ERR: file not found");
                return true;
            }

            try
            {
                var fi = new FileInfo(path);
                SendLine(stream, "SIZE " + fi.Length);

                using (var fs = fi.OpenRead())
                {
                    byte[] buf = new byte[Config.BufferSize];
                    int read;
                    while ((read = fs.Read(buf, 0, buf.Length)) > 0)
                    {
                        if (!stream.Send(buf, 0, read))
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                SendLine(stream, "ERR: " + ex.Message);
            }

            return true;
        }

        private static void SendLine(IShellStream stream, string msg)
        {
            byte[] data = Encoding.UTF8.GetBytes(msg + "\n");
            stream.Send(data, 0, data.Length);
        }
    }
}
