using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace SslConsoleServer
{
    class Program
    {
        static bool CertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            try
            {
                var serverCertificate = new X509Certificate2("certificate.pfx", "1234");

                byte[] clientCertBytes = certificate.GetRawCertData();
                byte[] serverCertBytes = serverCertificate.GetRawCertData();

                if (clientCertBytes.Length != serverCertBytes.Length)
                {
                    throw new Exception("Client/server certificates do not match.");
                }

                for (int i = 0; i < clientCertBytes.Length; i++)
                {
                    if (clientCertBytes[i] != serverCertBytes[i])
                    {
                        throw new Exception("Client/server certificates do not match.");
                    }
                }
            }
            catch
            {
                return false;
            }

            return true;
        }

        static void Main(string[] args)
        {
            var certificate = new X509Certificate2("vera-tls-certificate.pfx", "1234");

            //Starts Tcp Listener
            var listener = new TcpListener(IPAddress.Loopback, 5300);
            listener.Start();

            //Wait for clients
            var client = listener.AcceptTcpClient();

            //Get client stream
            var stream = client.GetStream();


            //SslStream sslStream = new SslStream(stream, false);

            SslStream sslStream = new SslStream(
                stream,
                true,
                new RemoteCertificateValidationCallback(CertificateValidationCallback));

            sslStream.AuthenticateAsServer(certificate, true, SslProtocols.Tls12, false);

            //Read messages through SSLStream
            byte[] buffer = new byte[client.ReceiveBufferSize];
            while (client.Connected)
            {
                int bytesRead = sslStream.Read(buffer, 0, client.ReceiveBufferSize);
                Console.WriteLine(Encoding.ASCII.GetString(buffer, 0, bytesRead));
            }
        }

    }
}
