using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace SslConsoleClient
{
    class Program
    {
        static void Main(string[] args)
        {
            var certificate = new X509Certificate2("etb-tls-certificate-android.pfx", "1234");
            var certificateCollection = new X509CertificateCollection();
            certificateCollection.Add(certificate);


            //Create tcp client
            TcpClient client = new TcpClient("127.0.0.1", 5300);
            var stream = client.GetStream();

            //Wrap the stream and use "RemoteCertificateValidationCallback" in some way that allows all certificates
            SslStream sslStream = new SslStream(stream, false, new RemoteCertificateValidationCallback(CertificateValidationCallback));

            //Authenticate 
            sslStream.AuthenticateAsClient("clientName", certificateCollection, false);

            //Start sending encrypted messages
            string message = "wake up,neo";
            while (true)
            {
                sslStream.Write(Encoding.UTF8.GetBytes(message), 0, message.Length);
            }

        }

        //Callback function that allows all certificates
        static bool CertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
}
