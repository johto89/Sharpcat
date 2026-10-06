using System;
using System.Net.Sockets;

namespace SvcUtil
{
    internal sealed class CryptoStream : IShellStream
    {
        private readonly Socket _socket;
        private readonly byte[] _key;
        private int _sendIdx;
        private int _recvIdx;

        public CryptoStream(Socket socket, byte[] key)
        {
            if (socket == null) throw new ArgumentNullException("socket");
            if (key == null) throw new ArgumentNullException("key");
            if (key.Length == 0)
                throw new ArgumentException("Key must not be empty", "key");
            _socket = socket;
            _key = key;
            _sendIdx = 0;
            _recvIdx = 0;
        }

        public bool Connected { get { return _socket.Connected; } }

        /// <summary>
        /// Send data with XOR encryption applied.
        /// </summary>
        public bool Send(byte[] buffer, int offset, int count)
        {
            if (count <= 0) return true;

            byte[] cipher = new byte[count];
            for (int i = 0; i < count; i++)
            {
                cipher[i] = (byte)(buffer[offset + i] ^ _key[_sendIdx % _key.Length]);
                _sendIdx++;
            }

            int totalSent = 0;
            while (totalSent < count)
            {
                SocketError err;
                int sent = _socket.Send(cipher, totalSent, count - totalSent,
                                        SocketFlags.None, out err);
                if (err != SocketError.Success || sent <= 0)
                    return false;
                totalSent += sent;
            }
            return true;
        }

        /// <summary>
        /// Receive data and decrypt XOR in place.
        /// Returns number of bytes received, or -1 on error.
        /// </summary>
        public int Receive(byte[] buffer, int offset, int count)
        {
            SocketError err;
            int received = _socket.Receive(buffer, offset, count,
                                           SocketFlags.None, out err);
            if (err != SocketError.Success || received <= 0)
                return -1;

            for (int i = 0; i < received; i++)
            {
                buffer[offset + i] ^= _key[_recvIdx % _key.Length];
                _recvIdx++;
            }
            return received;
        }

        public void Close()
        {
            try { _socket.Shutdown(SocketShutdown.Both); } catch { }
            try { _socket.Close(); } catch { }
        }
    }
}
