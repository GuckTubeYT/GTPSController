using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace GTPSControllerClient
{
    class Program
    {
        private const int MF_BYCOMMAND = 0x00000000;
        public const int SC_CLOSE = 0xF060;

        [DllImport("user32.dll")]
        public static extern int DeleteMenu(IntPtr hMenu, int nPosition, int wFlags);

        [DllImport("user32.dll")]
        private static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern IntPtr GetConsoleWindow();

        static void Main(string[] args)
        {
            Console.WriteLine("[!] GTPSControllerClient Made By: GuckTube YT");
            Console.WriteLine("[!] Credit: egezx\n[!] WARNING: ");
            Console.Write("[?] Please Enter IP Server: ");
            string ip = (Console.ReadLine());

            Console.Write("[?] Please Enter Port Server (Default = 18091): ");
            string pstring = (Console.ReadLine());
            int port;
            Int32.TryParse(pstring, out port);

            Console.Write("[?] Please Enter Password: ");
            string password = (Console.ReadLine());
            Console.WriteLine("\n[+] Connecting to " + ip);
            UdpClient client = new UdpClient();
            IPEndPoint ipep = new IPEndPoint(IPAddress.Parse(ip), port);
            client.Connect(ipep);
            byte[] packet = Encoding.ASCII.GetBytes("Connecting...");
            client.Send(packet, packet.Length);
            var data = client.Receive(ref ipep);
            if (data[0] == 0x02)
            {
                data = data.Skip(1).ToArray();

                string token = Encoding.ASCII.GetString(data);
                string response = ComputeHash(token + password);


                Console.WriteLine("[+] Received authentication token: " + token);
                Console.WriteLine("[+] Computed password hash: " + response);

                byte[] resp = Encoding.ASCII.GetBytes(response);
                client.Send(resp, resp.Length);

                data = client.Receive(ref ipep);

                if (data[0] == 0x00)
                {
                    Console.WriteLine("[-] The Password is Wrong\nPress Any Key to Quit...");
                    Console.ReadLine();
                    client.Close();
                    Environment.Exit(0);
                    return;
                }

                if (data[0] == 0x01)
                {
                    Console.WriteLine("[+] Authentication Succeeded");
                    Console.WriteLine("[+] Client has been connected to Server!\n[!] WARNING: If you want to close this app, Please type disconnect\n");
                }
                if (data[0] == 0xFF)
                {
                    data = data.Skip(1).ToArray();
                    Console.WriteLine(Encoding.ASCII.GetString(data));
                }
            }
            while (true)
            {
                DeleteMenu(GetSystemMenu(GetConsoleWindow(), false), SC_CLOSE, MF_BYCOMMAND);
                Console.Write("[?] Command: ");
                string type = (Console.ReadLine());
                byte[] packet1 = Encoding.ASCII.GetBytes(type);
                client.Send(packet1, packet1.Length);
                var data1 = client.Receive(ref ipep);
                Console.WriteLine("[+] Command Has been Sended to Server!\n");
                if (data1[0] == 0xFF)
                {
                    data1 = data1.Skip(1).ToArray();
                    Console.WriteLine("[+] Request From Server:\n" + Encoding.ASCII.GetString(data1) + "\n");
                }
                if (type == "disconnect")
                {
                    client.Close();
                    Console.WriteLine("[+] Server Successfully Disconnected!");
                    return;
                }
            }
        }


        public static String ComputeHash(String value)
        {
            using (SHA256 hash = SHA256Managed.Create())
            {
                return String.Join("", hash.ComputeHash(Encoding.UTF8.GetBytes(value)).Select(item => item.ToString("x2")));
            }
        }


    }
}