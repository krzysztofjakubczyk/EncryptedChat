using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Serwer
{
    internal class Program
    {
        static TcpListener listener;
        static List<Client> users;
        static public ECDiffieHellmanCng _ecdh;
        static public byte[] DHserversPublicKey;
        static public RSACng rsaServer; // Dodajemy RSA dla serwera
        public static Dictionary<Guid, byte[]> clientPublicKeysRSA;
        public static Dictionary<Guid, byte[]> clientPublicKeysDH;
        static void Main(string[] args)
        {
            users = new List<Client>();
            clientPublicKeysRSA = new Dictionary<Guid, byte[]>();
            clientPublicKeysDH = new Dictionary<Guid, byte[]>();
            listener = new TcpListener(IPAddress.Parse("127.0.0.1"), 7891);
            listener.Start();

            _ecdh = new ECDiffieHellmanCng
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256
            };
            DHserversPublicKey = _ecdh.PublicKey.ToByteArray();

            rsaServer = new RSACng(2048);

            Console.WriteLine("Server started. Listening for connections...");
            Task.Run(async () =>
            {
                while (true)
                {
                    var client = new Client(await listener.AcceptTcpClientAsync());
                    users.Add(client);
                    Console.WriteLine($"{client.Username} connected.");
                    BroadcastConnection();
                }
            });

            Console.ReadLine(); // Prevent the main thread from exiting
        }

        static void BroadcastConnection()
        {
            foreach (var user in users)
            {
                foreach (var usr in users)
                {
                    var broadcastPacket = new PacketBuilder();
                    broadcastPacket.WriteOpCode(1); // OpCode for broadcast connection
                    broadcastPacket.WriteMessage(usr.Username);
                    broadcastPacket.WriteMessage(usr.UID.ToString());
                    user.ClientSocket.Client.Send(broadcastPacket.GetPacketBytes());
                }
            }
        }

        public static void BroadcastDisconnectMessage(string uid)
        {
            foreach (var user in users)
            {
                var broadcastPacket = new PacketBuilder();
                broadcastPacket.WriteOpCode(10); // OpCode for disconnect message
                broadcastPacket.WriteMessage(uid);
                user.ClientSocket.Client.Send(broadcastPacket.GetPacketBytes());
                BroadcastMessage($"[{DateTime.Now}]: User has disconnected");
            }
        }

        public static void BroadcastMessage(string message)
        {
            foreach (var user in users)
            {
                byte[] iv;
                var encryptedMessage = AESEncryption.Encrypt(message, user.SharedKey, out iv);

                var messagePacket = new PacketBuilder();
                messagePacket.WriteOpCode(5);
                messagePacket.WriteMessage(Convert.ToBase64String(iv));

                using (SHA256 mySHA256 = SHA256.Create())
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(message);
                    byte[] hashedMessage = mySHA256.ComputeHash(bytes);

                    //Console.WriteLine($" ROZSYLANA WIADOMOSC Z SERWERA DO KLIENTA PO STRONIE SERWERA: {message}");
                    //Console.WriteLine($"Server - Hashed message: {Convert.ToBase64String(hashedMessage)}");

                    // Użycie klucza publicznego klienta do szyfrowania hasha
                    using (RSACng rsaCng = new RSACng())
                    {
                        if (clientPublicKeysRSA.TryGetValue(user.UID, out var publicKey))
                        {
                            rsaCng.ImportRSAPublicKey(publicKey, out _);
                            //Console.WriteLine("PUBLIC KEY DO PODPISU: " + Convert.ToBase64String(publicKey));
                            var encryptedHash = rsaCng.Encrypt(hashedMessage, RSAEncryptionPadding.OaepSHA256);
                            //Console.WriteLine($"Server - Encrypted hash: {Convert.ToBase64String(encryptedHash)}");

                            messagePacket.WriteMessage(Convert.ToBase64String(encryptedHash));
                            messagePacket.WriteMessage(Convert.ToBase64String(encryptedMessage));
                        }
                        else
                        {
                            Console.WriteLine($"Public key for client {user.UID} not found.");
                        }
                    }

                    user.ClientSocket.Client.Send(messagePacket.GetPacketBytes());
                }
            }
        }

        public static void StoreClientPublicKey(Guid uid, byte[] publicKeyDH, byte[] publicKeyRSA)
        {
            clientPublicKeysDH[uid] = publicKeyDH;
            clientPublicKeysRSA[uid] = publicKeyRSA;
            //Console.WriteLine($"Stored public key for client {uid}: {Convert.ToBase64String(publicKeyRSA)}");
        }
    }
}
