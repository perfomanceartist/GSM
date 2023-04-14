using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace GSMLib
{
    public class Client
    {
        TcpClient tcpClient;
        string serverAddress = "127.0.0.1";
        int serverPort = 9000;
        NetworkStream stream;
        Cryptography.AuthTriplet authTriplet;
        Cryptography.A5 encryptor;
        public Client()
        {
            tcpClient = new TcpClient();
            authTriplet = new Cryptography.AuthTriplet();
            encryptor = new Cryptography.A5();
        }

        ~Client() {
            tcpClient.Close();
        }


        public bool Connect()
        {
            try
            {
                tcpClient.Connect(serverAddress, serverPort);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in client connect:");
                Console.WriteLine(ex.Message);
                return false;
            }
            stream = tcpClient.GetStream();
            return true;

        }


        public bool Authenticate(string password)
        {
            if (!AuthRequest()) return false;
            if (!ReceiveRAND()) return false;
            if (!SendSRES(password)) return false;
            if (!ReceiveAuthReply()) return false;
            return true;
        }

        public bool AuthRequest()
        {
            try
            {
                stream.Write(Encoding.UTF8.GetBytes("Auth Request"));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in client auth request:");
                Console.WriteLine(ex.Message);
                return false;
            }
            return true;
        }

        public bool ReceiveRAND()
        {
            byte[] receivedData = new byte[64];
            try
            {
                stream.Read(receivedData);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in client receiving RAND:");
                Console.WriteLine(ex.Message);
                return false;
            }
            receivedData.CopyTo(authTriplet.RAND, 0);
            return true;
        }

        public bool SendSRES(string KI)
        {
            authTriplet = Cryptography.GetAuthTriplet(authTriplet.RAND, KI);
            encryptor.Initialise(authTriplet.KC);

            try
            {
                stream.Write(authTriplet.SRES);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in client sending SRES:");
                Console.WriteLine(ex.Message);
                return false;
            }
            return true;
        }

        public bool ReceiveAuthReply()
        {
            byte[] reply = new byte[64];
            int len;
            try
            {
                len = stream.Read(reply);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in client receiving Auth Reply:");
                Console.WriteLine(ex.Message);
                return false;
            }
            string answer = Encoding.UTF8.GetString(reply, 0, len);
            if (answer != "ok")
            {
                Console.WriteLine("Authentication was not successful.");
                return false;
            }
            return true;
        }


    }
}
