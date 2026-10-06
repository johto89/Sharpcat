namespace SvcUtil
{
    internal interface IShellStream
    {
        bool Connected { get; }

        /// <summary>Send data. Returns false on error.</summary>
        bool Send(byte[] buffer, int offset, int count);

        /// <summary>Receive data. Returns bytes received, or -1 on error.</summary>
        int Receive(byte[] buffer, int offset, int count);

        void Close();
    }
}
