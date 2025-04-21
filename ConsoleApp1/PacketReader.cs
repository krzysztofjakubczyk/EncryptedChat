using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace Serwer
{
    internal class PacketReader : BinaryReader
    {
        private NetworkStream _ns;

        public PacketReader(NetworkStream ns) : base(ns)
        {
            _ns = ns ?? throw new ArgumentNullException(nameof(ns));
        }

        public string ReadMessage()
        {
            try
            {
                int length = ReadInt32(); // Czytaj długość wiadomości (4 bajty)
                byte[] msgBuffer = new byte[length];
                int bytesRead = 0;
                int bytesToRead = length;

                // Pętla czytająca dane z _ns, dopóki nie odczytamy wszystkich oczekiwanych bajtów
                while (bytesToRead > 0)
                {
                    int n = _ns.Read(msgBuffer, bytesRead, bytesToRead);
                    if (n == 0)
                    {
                        throw new IOException("Unexpected end of stream.");
                    }
                    bytesRead += n;
                    bytesToRead -= n;
                }

                string msg = Encoding.ASCII.GetString(msgBuffer);
                return msg;
            }
            catch (Exception ex)
            {
                throw new IOException("Error reading message from network stream.", ex);
            }
        }
    }
}
