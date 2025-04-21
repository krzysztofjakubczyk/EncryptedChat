using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Serwer
{
    internal class Client
    {
        public string Username { get; set; }
        public Guid UID;
        public TcpClient ClientSocket;
        PacketReader _packetReader;
        PacketBuilder _packetBuilder;
        public bool _isConnected;

        public byte[] clientsPublicKeyDH { get; private set; }
        public byte[] clientsPublicKeyRSA { get; private set; }
        public byte[] SharedKey { get; private set; }

        public Client(TcpClient client)
        {
            ClientSocket = client;
            UID = Guid.NewGuid();
            _packetReader = new PacketReader(ClientSocket.GetStream());

            var opcode = _packetReader.ReadByte();
            Username = _packetReader.ReadMessage();

            _packetBuilder = new PacketBuilder();
            _isConnected = true;
            Console.WriteLine($"[{DateTime.Now}]: Client connected with name: {Username}");
            Task.Run(() => Process());

            // Sending server's public key to the client
            _packetBuilder.WriteOpCode(2); // OpCode for sending server's public key
            _packetBuilder.WriteMessage(Convert.ToBase64String(Program.DHserversPublicKey));
            _packetBuilder.WriteMessage(Convert.ToBase64String(Program.rsaServer.ExportRSAPublicKey()));

            ClientSocket.Client.Send(_packetBuilder.GetPacketBytes());
        }

        void Process()
        {
            while (true)
            {
                try
                {
                    var opcode = _packetReader.ReadByte();
                    switch (opcode)
                    {
                        case 5:
                            var iv = Convert.FromBase64String(_packetReader.ReadMessage()); // Receiving IV
                            var onesEncryptedHashFromClient = Convert.FromBase64String(_packetReader.ReadMessage()); // Receiving RSA Hash
                            var encryptedMessage = Convert.FromBase64String(_packetReader.ReadMessage()); // Receiving encrypted message

                            // Decrypting message using AES
                            string decryptedMessage = AESEncryption.Decrypt(encryptedMessage, SharedKey, iv);
                            //Console.WriteLine("WIADOMOSC OD KLIENTA PO STRONIE SERWERA ZDEKRYPTOWANA: " +  decryptedMessage);   
                            //Decrypting zaszyfrowany podpis
                            byte[] decryptedHash;
                            decryptedHash = Program.rsaServer.Decrypt(onesEncryptedHashFromClient, RSAEncryptionPadding.OaepSHA256);

                            // Comparing decrypted hash with computed hash
                            using (SHA256 sha256 = SHA256.Create())
                            {
                                byte[] computedHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(decryptedMessage));
                                if (computedHash.SequenceEqual(decryptedHash))
                                {
                                    Console.WriteLine($"[{DateTime.Now}]: Message received from client: {decryptedMessage}");
                                    Program.BroadcastMessage($"[{Username}]: {decryptedMessage}");
                                }

                                else
                                {
                                    Console.WriteLine($"[{DateTime.Now}]: Message hash verification failed.");
                                }
                            }


                            break;
                        case 2: // OpCode for receiving client's public key
                            clientsPublicKeyDH = Convert.FromBase64String(_packetReader.ReadMessage());
                            clientsPublicKeyRSA = Convert.FromBase64String(_packetReader.ReadMessage());
                            SharedKey = Program._ecdh.DeriveKeyMaterial(CngKey.Import(clientsPublicKeyDH, CngKeyBlobFormat.EccPublicBlob));
                            //Console.WriteLine($"Shared key established with {Username}: {Convert.ToBase64String(SharedKey)}");

                            // Store client's public keys in Program
                            Program.StoreClientPublicKey(UID, clientsPublicKeyDH, clientsPublicKeyRSA);
                            break;
                        default:
                            break;
                    }
                }



                catch (Exception)
                {
                    Console.WriteLine($"[{UID.ToString()}]: Disconnected");
                    Program.BroadcastDisconnectMessage(UID.ToString());
                    ClientSocket.Close();
                    break;
                }
            }
        }
    }
}
