 /*
 * GTPSControllerServer (C) GuckTube YT
 * Credit: egezx
 * This is Server, you can control it with Client
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;

namespace GTPSControllerServer
{
    class Program
    {
        public const byte HEADER_AUTH_FAILED = 0x00;
        public const byte HEADER_AUTH_SUCCEEDED = 0x01;
        public const byte HEADER_AUTH_TOKEN = 0x02;
        public const byte HEADER_SERVER_RESPONSE = 0xFF;
        public const string sdata = @"C:\xampp\htdocs\growtopia\server_data.php";
        public static List<ClientInfo> clientList = new List<ClientInfo>();
        public static UdpClient serverSocket = null;
        public static IPEndPoint clientEndpoint = null;
        public static byte[] receivedData = null;

        static void Main(string[] args)
        {
            Console.WriteLine("[!] GTPSControllerServer (C) GuckTube YT");
            Console.WriteLine("[!] Credit: egezx\n");

            if (!File.Exists("portcontroller.txt"))
            {
                Console.WriteLine("[-] portcontroller.txt Not Found!");
                Console.Write("[?] Please Enter port number (Default = 18091): ");
                string pstring = (Console.ReadLine());
                int port1;
                Int32.TryParse(pstring, out port1);
                Console.WriteLine("[+] Creating portcontroller.txt...");
                using (System.IO.StreamWriter file =
            new System.IO.StreamWriter("portcontroller.txt", false))
                {
                    file.Write(port1);
                    file.Close();
                }
                Console.WriteLine("[+] portcontroller.txt Has Been Created!");
            }

            if (!File.Exists("passcontroller.txt"))
            {
                Console.WriteLine("[-] passcontroller.txt Not Found!");
                Console.Write("[?] Please fill the Password: ");
                string pass = (Console.ReadLine());
                Console.WriteLine("[+] Creating passcontroller.txt...");
                using (System.IO.StreamWriter file =
            new System.IO.StreamWriter("passcontroller.txt", false))
                {
                    file.Write(pass);
                    file.Close();
                }
                Console.WriteLine("[+] passcontroller.txt Has Been Created!");
            }
            string ps = File.ReadAllText("portcontroller.txt");
            Console.WriteLine("[+] Port Server: " + ps);
            string pass1 = File.ReadAllText("passcontroller.txt");
            Console.WriteLine("[+] Password: " + pass1);
            Console.WriteLine("[+] Server has been Started!\n");
            Console.WriteLine("============================[LOGS]============================");
            while (true)
            {
                string pstring1 = File.ReadAllText("portcontroller.txt");
                int port;
                Int32.TryParse(pstring1, out port);
                serverSocket = new UdpClient(port);
                clientEndpoint = new IPEndPoint(IPAddress.Any, 0);
                receivedData = serverSocket.Receive(ref clientEndpoint);
                serverSocket.Connect(clientEndpoint);
                ClientStatus cs = CheckAuthenticationStatus(clientEndpoint.Address);

                switch (cs)
                {
                    case ClientStatus.CLIENT_AUTH_NEW:
                        GenerateSendToken();
                        break;

                    case ClientStatus.CLIENT_AUTH_RECEIVED:
                        CheckAuthResponse(receivedData);
                        break;

                    case ClientStatus.CLIENT_AUTH_OK:
                        HandleData(receivedData);
                        break;
                }

                serverSocket.Close();
            }
        }

        public static void HandleData(byte[] data)
        {
            string rmassage = Encoding.ASCII.GetString(data);
            if (rmassage == "help")
            {
                Console.WriteLine("[+] Received From Client: " + rmassage);
                var resp = Encoding.ASCII.GetBytes("[?] Commands are\n[?] startserver = Start the Server\n[?] stopserver = Stop the Server\n[?] disconnect = Disconnect the Client\n[?] maintenance start = Start the Maintenance\n[?] maintenance stop = Stop the Maintenance");
                serverSocket.Send((new byte[] { HEADER_SERVER_RESPONSE }).Concat(resp).ToArray(), resp.Length + 1);
            }

            else if (rmassage == "startserver")
            {
                Console.WriteLine("[+] Received From Client: " + rmassage);
                if (!File.Exists("enet.exe"))
                {
                    var resp1 = Encoding.ASCII.GetBytes("[-] enet.exe Not Found! please change gtps exe to enet.exe, and put this app to your gtps folder");
                    serverSocket.Send((new byte[] { HEADER_SERVER_RESPONSE }).Concat(resp1).ToArray(), resp1.Length + 1);
                    return;
                }
                Process.Start("enet.exe");
                var resp2 = Encoding.ASCII.GetBytes("[+] Server has been Started!");
                serverSocket.Send((new byte[] { HEADER_SERVER_RESPONSE }).Concat(resp2).ToArray(), resp2.Length + 1);
                return;
            }

            else if (rmassage == "stopserver")
            {
                Console.WriteLine("[+] Received From Client: " + rmassage);
                Console.WriteLine("[+] Stopping the Server...");
                foreach (var process in Process.GetProcessesByName("enet.exe"))
                {
                    process.Kill();
                }
                foreach (var process in Process.GetProcessesByName("enet"))
                {
                    process.Kill();
                }
                Console.WriteLine("[+] Server has been Stopped!");
                var resp = Encoding.ASCII.GetBytes("[+] Server has been Stopped!");
                serverSocket.Send((new byte[] { HEADER_SERVER_RESPONSE }).Concat(resp).ToArray(), resp.Length + 1);
            }

            else if (rmassage == "disconnect")
            {
                Console.WriteLine("[+] Received From Client: " + rmassage + "\n");
                var resp1 = Encoding.ASCII.GetBytes("[+] Disconnecting...");
                serverSocket.Send((new byte[] { HEADER_SERVER_RESPONSE }).Concat(resp1).ToArray(), resp1.Length + 1);
                Console.WriteLine("[+] Disconnecting Client...");
                int clientId = GetClientIdByIp(clientEndpoint.Address);
                clientList.RemoveAt(clientId);
                Console.WriteLine("[+] Client has Been Disconnected!\n");
            }
            else if (rmassage == "maintenance start")
            {
                Console.WriteLine("[+] Received From Client: " + rmassage);
                Console.WriteLine("[+] Starting the Maintenance...");
                if (!File.Exists(sdata))
                {
                    Console.WriteLine("[-] server_data.php Not Found! Please set sdata");
                    var resp1 = Encoding.ASCII.GetBytes("[-] server_data.php Not Found! Please set sdata");
                    serverSocket.Send((new byte[] { HEADER_SERVER_RESPONSE }).Concat(resp1).ToArray(), resp1.Length + 1);
                    return;
                }
                string text = File.ReadAllText(sdata);
                text = text.Replace("#maint|", "maint|");
                File.WriteAllText(sdata, text);
                Console.WriteLine("[+] Server has been Maintenanced!");
                var resp = Encoding.ASCII.GetBytes("[+] Server has been Maintenanced!");
                serverSocket.Send((new byte[] { HEADER_SERVER_RESPONSE }).Concat(resp).ToArray(), resp.Length + 1);
            }
            else if (rmassage == "maintenance stop")
            {
                Console.WriteLine("[+] Received From Client: " + rmassage);
                Console.WriteLine("[+] Stopping the Maintenance...");
                if (!File.Exists(sdata))
                {
                    Console.WriteLine("[-] server_data.php Not Found! Please set sdata");
                    var resp1 = Encoding.ASCII.GetBytes("[-] server_data.php Not Found! Please set sdata");
                    serverSocket.Send((new byte[] { HEADER_SERVER_RESPONSE }).Concat(resp1).ToArray(), resp1.Length + 1);
                    return;
                }
                string text1 = File.ReadAllText(sdata);
                text1 = text1.Replace("maint|", "#maint|");
                File.WriteAllText(sdata, text1);
                Console.WriteLine("[+] the Server has been stopping Maintenance!");
                var resp = Encoding.ASCII.GetBytes("[+] the Server has been stopping Maintenance!");
                serverSocket.Send((new byte[] { HEADER_SERVER_RESPONSE }).Concat(resp).ToArray(), resp.Length + 1);
            }
            else
            {
                string receivedMessage1 = Encoding.ASCII.GetString(data);
                Console.WriteLine("[+] Received From Client: " + receivedMessage1);
                var response1 = Encoding.ASCII.GetBytes("[-] Command Not Found!, Please Type help for showing list commands");
                serverSocket.Send((new byte[] { HEADER_SERVER_RESPONSE }).Concat(response1).ToArray(), response1.Length + 1);
            }
        }

        public static void CheckAuthResponse(byte[] data)
        {
            string response = Encoding.ASCII.GetString(data);
            int clientId = GetClientIdByIp(clientEndpoint.Address);
            string password = File.ReadAllText("passcontroller.txt");
            if (response.Equals(ComputeHash(clientList[clientId].token + password)))
            {
                clientList[clientId].authenticated = true;
                serverSocket.Send(new byte[] { HEADER_AUTH_SUCCEEDED }, 1);
                Console.WriteLine("[+] Authentication Succeeded!");
                Console.WriteLine("[+] Client has been Connected to this Server!\n");
                return;
            }
            clientList.RemoveAt(clientId);
            serverSocket.Send(new byte[] { HEADER_AUTH_FAILED }, 1);
            Console.WriteLine("[-] Authentication Failure!");
            Console.WriteLine("[-] Client is failed to connect this Server, because the password is Wrong!\n");
            return;
        }

        public static void GenerateSendToken()
        {
            string guidString = Guid.NewGuid().ToString();
            byte[] guid = Encoding.ASCII.GetBytes(guidString);
            byte[] finalPacket = (new byte[] { HEADER_AUTH_TOKEN }).Concat(guid).ToArray();

            serverSocket.Send(finalPacket, finalPacket.Length);

            clientList.Add(new ClientInfo(clientEndpoint.Address));
            clientList[GetClientIdByIp(clientEndpoint.Address)].token = guidString;
        }

        public static ClientStatus CheckAuthenticationStatus(IPAddress ip)
        {

            ClientInfo clientdata = GetClientInfoByIp(ip);

            if (clientdata != null)
            {
                if (clientdata.authenticated)
                    return ClientStatus.CLIENT_AUTH_OK;

                else
                    return ClientStatus.CLIENT_AUTH_RECEIVED;
            }

            else
                return ClientStatus.CLIENT_AUTH_NEW;

        }

        public static ClientInfo GetClientInfoByIp(IPAddress ip)
        {
            return clientList.Find(i => (i.ip.Equals(ip)));
        }

        public static int GetClientIdByIp(IPAddress ip)
        {
            return clientList.FindIndex(i => (i.ip.Equals(ip)));
        }

        public static String ComputeHash(String value)
        {
            using (SHA256 hash = SHA256Managed.Create())
            {
                return String.Join("", hash.ComputeHash(Encoding.UTF8.GetBytes(value)).Select(item => item.ToString("x2")));
            }
        }

    }

    class ClientInfo
    {
        public IPAddress ip;
        public bool authenticated = false;
        public string token;

        public ClientInfo(IPAddress ip = null)
        {
            this.ip = ip;
        }
    }

    enum ClientStatus
    {
        CLIENT_AUTH_NEW = 0,
        CLIENT_AUTH_RECEIVED = 2,
        CLIENT_AUTH_OK = 1
    };
}
