using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace SvcUtil
{
    internal sealed class TlsStream : IShellStream
    {
        private readonly Socket _socket;
        private readonly NetworkStream _netStream;
        private readonly SslStream _sslStream;
        private bool _authenticated;

        /// <summary>
        /// Wrap an existing connected socket in TLS.
        /// Call Authenticate() after construction to complete the handshake.
        /// </summary>
        public TlsStream(Socket socket)
        {
            if (socket == null) throw new ArgumentNullException("socket");
            _socket = socket;
            _netStream = new NetworkStream(socket, ownsSocket: false);
            _sslStream = new SslStream(
                _netStream,
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: AcceptAnyCert);
        }

        /// <summary>
        /// Complete TLS handshake as client.
        /// </summary>
        public bool Authenticate(string targetHost = "svcutil")
        {
            try
            {
                _sslStream.AuthenticateAsClient(targetHost);
                _authenticated = true;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool Connected { get { return _socket.Connected && _authenticated; } }

        public bool Send(byte[] buffer, int offset, int count)
        {
            if (count <= 0) return true;
            try
            {
                _sslStream.Write(buffer, offset, count);
                _sslStream.Flush();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public int Receive(byte[] buffer, int offset, int count)
        {
            try
            {
                int read = _sslStream.Read(buffer, offset, count);
                return read > 0 ? read : -1;
            }
            catch
            {
                return -1;
            }
        }

        public void Close()
        {
            try { if (_sslStream != null) _sslStream.Close(); } catch { }
            try { if (_netStream != null) _netStream.Close(); } catch { }
            try { if (_socket != null) _socket.Shutdown(SocketShutdown.Both); } catch { }
            try { if (_socket != null) _socket.Close(); } catch { }
        }

        /// <summary>
        /// Accept any server certificate.
        /// </summary>
        private static bool AcceptAnyCert(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
}
