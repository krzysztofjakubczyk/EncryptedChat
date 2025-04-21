using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Serwer
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
        public void WriteBytes(byte[] data)
        {
            _ms.Write(data, 0, data.Length);
        }
        public void WriteInt32(int value)
        {
            byte[] intBytes = BitConverter.GetBytes(value);
            _ms.Write(intBytes, 0, intBytes.Length);
        }
    }
}