using System.IO;
using System.Text;

namespace Client
{
    class PacketBuilder
    {
        private MemoryStream _ms;

        public PacketBuilder()
        {
            _ms = new MemoryStream();
        }

        public void WriteOpCode(byte opcode)
        {
            _ms.WriteByte(opcode);
        }

        public void WriteMessage(string message)
        {
            byte[] msgBytes = Encoding.UTF8.GetBytes(message);
            int msgLength = msgBytes.Length;
            _ms.Write(BitConverter.GetBytes(msgLength), 0, 4);
            _ms.Write(msgBytes, 0, msgLength);
        }

        public byte[] GetPacketBytes()
        {
            return _ms.ToArray();
        }
        public void WriteBytes(byte[] bytes)
        {
            _ms.Write(bytes, 0, bytes.Length);
        }
    }
}
