using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using static GSMLib.Cryptography;

namespace GSMLib
{
    public class Server
    {
        string clientKI = "IBKS";
        TcpListener tcpListener;
        public string serverIP = "127.0.0.1";
        public int serverPort = 9000;
        public NetworkStream stream;
        public Socket clientSocket;
        public Cryptography.AuthTriplet authTriplet;
        public Cryptography.A5 encryptor;
        public Server()
        {
            tcpListener = new TcpListener(IPAddress.Any, serverPort);
            tcpListener.Start();
            encryptor = new A5();
        }

        ~Server()
        {
            tcpListener.Stop();
        }

        public bool Work()
        {
            tcpListener.Start();
            while (true)
            {
                Console.WriteLine("---------------------------------------");
                try
                {
                    clientSocket = tcpListener.AcceptSocket();
                    Console.WriteLine("Client accepted");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error in server accept");
                    Console.WriteLine(ex.Message);
                    return false;
                }
                if (!AuthenticateClient())
                {
                    Console.WriteLine("Authentication was not successful");
                    clientSocket.Close();
                    continue;
                }
                Console.WriteLine("Client authenticated");

                while (clientSocket.Connected)
                {
                    string received;
                    if (!ReceiveData(out received)) break;
                    Console.WriteLine("Received Data: " + received);
                    if (!SendData("Received!")) break;
                }
            }
        }
        public bool ReceiveAuthRequest()
        {
            byte[] data = new byte[64];
            try
            {
                int len = clientSocket.Receive(data);
                string req = Encoding.UTF8.GetString(data, 0, len);
                Console.WriteLine("Received request: " + req);
                if (req != "Auth Request")
                {
                    Console.WriteLine("Wrong Auth Request");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in server receiving auth request");
                Console.WriteLine(ex.Message);
                return false;
            }
            return true;
        }

        public bool AuthenticateClient()
        {
            if (!ReceiveAuthRequest()) return false;
            if (!SendRAND()) return false;
            if (!ReceiveSRES()) return false;
            if (!SendAuthReply()) return false;
            return true;
        }


        public bool SendRAND()
        {
            authTriplet = Cryptography.GetAuthTriplet(clientKI);
            encryptor.Initialise(authTriplet.KC);
            try
            {
                clientSocket.Send(authTriplet.RAND);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in server sending RAND");
                Console.WriteLine(ex.Message);
                return false;
            }
            return true;
        }

        public bool ReceiveSRES ()
        {
            byte[] data = new byte[64];
            try
            {
                clientSocket.Receive(data);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in server receiving auth request");
                Console.WriteLine(ex.Message);
                return false;
            }

            if (data.Length < (int)AuthTripletLengths.SRES)
            {
                Console.WriteLine("Length of received SRES is not enough");
                return false;
            }
            for (int i = 0; i < (int)AuthTripletLengths.SRES; i++)
            {
                if (data[i] != authTriplet.SRES[i]) return false;
            }
            return true;
        }

        public bool SendAuthReply()
        {
            try
            {
                clientSocket.Send(Encoding.UTF8.GetBytes("ok"));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in server sending auth reply (ok)");
                Console.WriteLine(ex.Message);
                return false;
            }
            return true;
        }


        public bool SendData(string data)
        {
            try
            {
                byte[] origData = Encoding.UTF8.GetBytes(data);
                byte[] encrypted = encryptor.Encrypt(origData);
                clientSocket.Send(encrypted);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in server sending data");
                Console.WriteLine(ex.Message);
                return false;
            }
            return true;
        }

        public bool ReceiveData(out string data)
        {
            try
            {
                byte[] encrypted = new byte[1024];
                int len = clientSocket.Receive(encrypted);
                Array.Resize<byte>(ref encrypted, len);
                byte[] decrypted = encryptor.Decrypt(encrypted);
                data = Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in client receiving data");
                Console.WriteLine(ex.Message);
                data = "";
                return false;
            }
            return true;
        }

        
    }
}
