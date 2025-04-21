using System.IO;
using System.Net.Sockets;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;

namespace Client
{
    class Server
    {
        TcpClient _client;
        NetworkStream _stream;
        public PacketReader _packetReader;
        public event Action connectedEvent;
        public event Action msgReceivedEvent;
        public event Action userDisconnectedEvent;
        private ECDiffieHellmanCng _clientDH;
        private byte[] _clientPublicKey;
        private byte[] serversPublicKeyDH;
        private byte[] serversPublicKeyRSA;
        private byte[] _sharedKey;
        public event Action<string> messageReceivedEvent;
        private RSACng rsaClient;
        private byte[] _clientsPublicKeyRSa;

        public Server()
        {
            _client = new TcpClient();
            _clientDH = new ECDiffieHellmanCng
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256
            };
            _clientPublicKey = _clientDH.PublicKey.ToByteArray();
        }

        public void ConnectToServer(string username)
        {
            if (!_client.Connected)
            {
                _client.Connect("127.0.0.1", 7891);
                _stream = _client.GetStream();
                _packetReader = new PacketReader(_stream);

                // Send connection packet
                var connectPacket = new PacketBuilder();
                connectPacket.WriteOpCode(0); // OpCode for connection packet
                connectPacket.WriteMessage(username);
                _stream.Write(connectPacket.GetPacketBytes(), 0, connectPacket.GetPacketBytes().Length);

                Task.Run(ReadPackets);
            }
        }

        private void ReadPackets()
        {
            while (true)
            {
                try
                {
                    var packetReader = new PacketReader(_stream);
                    var opcode = packetReader.ReadByte();
                    switch (opcode)
                    {
                        case 1:
                            connectedEvent?.Invoke();

                            break;
                        case 2: // OpCode for receiving server's public key
                            var serverPublicKeyStringDH = packetReader.ReadMessage();
                            serversPublicKeyDH = Convert.FromBase64String(serverPublicKeyStringDH);
                            var serverPublicKeyStringRSA = packetReader.ReadMessage();
                            serversPublicKeyRSA = Convert.FromBase64String(serverPublicKeyStringRSA);
                            //messageReceivedEvent?.Invoke("Server's public key RSA: " + Convert.ToBase64String(serversPublicKeyRSA));


                            rsaClient = new RSACng(2048);
                            //rsaClient.ImportRSAPublicKey(serversPublicKeyRSA, out _);
                            //messageReceivedEvent?.Invoke("Client's public key RSA: " + Convert.ToBase64String(rsaClient.ExportRSAPublicKey()));
                            _sharedKey = _clientDH.DeriveKeyMaterial(CngKey.Import(serversPublicKeyDH, CngKeyBlobFormat.EccPublicBlob));

                            // Send client's public key to server
                            SendClientPublicKey();
                            break;
                        case 5:
                            var iv = Convert.FromBase64String(packetReader.ReadMessage());
                            var encryptedHash = Convert.FromBase64String(packetReader.ReadMessage());
                            var encryptedMessage = Convert.FromBase64String(packetReader.ReadMessage());
                            //messageReceivedEvent?.Invoke($"Client - Encrypted message hash: {Convert.ToBase64String(encryptedMessage)}");
                            var decryptedMessage = AESEncryption.Decrypt(encryptedMessage, _sharedKey, iv);

                            //messageReceivedEvent?.Invoke($"WIADOMOSC OD SERWERA: {decryptedMessage}");
                            var decryptedHash = rsaClient.Decrypt(encryptedHash, RSAEncryptionPadding.OaepSHA256);

                            using (SHA256 mySHA256 = SHA256.Create())
                            {
                                byte[] computedHash = mySHA256.ComputeHash(Encoding.UTF8.GetBytes(decryptedMessage));
                                //messageReceivedEvent?.Invoke($"Client - Decrypted hash: {Convert.ToBase64String(decryptedHash)}");
                                //messageReceivedEvent?.Invoke($"Client - Computed hash: {Convert.ToBase64String(computedHash)}");
                                if (computedHash.SequenceEqual(decryptedHash)) 
                                {
                                    messageReceivedEvent?.Invoke(decryptedMessage);
                                }
                                else
                                {
                                    messageReceivedEvent?.Invoke("TooBigMessage");
                                }
                            }
                            break;
                        case 10:
                            userDisconnectedEvent?.Invoke();
                            break;
                        default:
                            Console.WriteLine("Unknown opcode received.");
                            break;
                    }
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"Error reading packet: {ex.Message}");
                    userDisconnectedEvent?.Invoke();
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error processing packet: {ex.Message}");
                }
            }
        }

        private void SendClientPublicKey()
        {
            var keyExchangePacket = new PacketBuilder();
            keyExchangePacket.WriteOpCode(2); // OpCode for client's public key
            keyExchangePacket.WriteMessage(Convert.ToBase64String(_clientPublicKey));
            keyExchangePacket.WriteMessage(Convert.ToBase64String(rsaClient.ExportRSAPublicKey()));

            _stream.Write(keyExchangePacket.GetPacketBytes(), 0, keyExchangePacket.GetPacketBytes().Length);
        }

        public void SendMessageToServer(string message)
        {
            using (SHA256 mySHA256 = SHA256.Create())
            {
                //messageReceivedEvent?.Invoke($"Client - Send Message to server: {message}");

                // Obliczanie skrótu wiadomości
                byte[] bytes = Encoding.UTF8.GetBytes(message);
                byte[] hashedMessage = mySHA256.ComputeHash(bytes);

                // Szyfrowanie wiadomości AES   
                byte[] encryptedMessage;
                byte[] iv;
                encryptedMessage = AESEncryption.Encrypt(message, _sharedKey, out iv);

                byte[] signedHash;
                _clientsPublicKeyRSa = rsaClient.ExportRSAPublicKey();
                RSACng rsaCNG = new RSACng();
                rsaCNG.ImportRSAPublicKey(serversPublicKeyRSA, out _);
                signedHash = rsaCNG.Encrypt(hashedMessage, RSAEncryptionPadding.OaepSHA256);

                // Tworzenie pakietu wiadomości do wysłania
                var messagePacket = new PacketBuilder();
                messagePacket.WriteOpCode(5); // OpCode 5 for this type of message
                messagePacket.WriteMessage(Convert.ToBase64String(iv));
                messagePacket.WriteMessage(Convert.ToBase64String(signedHash));
                messagePacket.WriteMessage(Convert.ToBase64String(encryptedMessage));

                // Wysyłanie pakietu wiadomości do serwera
                _client.Client.Send(messagePacket.GetPacketBytes());

                Console.WriteLine("Message sent to server.");
            }
        }

    }
    }