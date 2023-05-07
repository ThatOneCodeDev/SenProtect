using System;
using System.Security.Cryptography;
using System.IO;

namespace EncryptionLibrary
{
    public class CryptographyRSA
    {
        private readonly RSACryptoServiceProvider rsa;

        public CryptographyRSA()
        {
            rsa = new RSACryptoServiceProvider();
        }

        public static void GenerateRSAKey(string publicKeyFile, string privateKeyFile)
        {
            // Generate a new RSA key pair
            RSACryptoServiceProvider rsa = new();

            // Save the public key data to a file
            File.WriteAllText(publicKeyFile, rsa.ToXmlString(includePrivateParameters: false));

            // Save the private key data to a file
            File.WriteAllText(privateKeyFile, rsa.ToXmlString(includePrivateParameters: true));
        }

        public void LoadRSAKey(string keyFile)
        {
            // Load the RSA key data from a file
            string keyData = File.ReadAllText(keyFile);

            // Import the RSA key data into the RSA object
            rsa.FromXmlString(keyData);
        }

        public byte[] RSAEncrypt(byte[] data, string publicKeyFile)
        {
            // Load the public RSA key data from a file
            LoadRSAKey(publicKeyFile);

            // Encrypt the data using the RSA object
            return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA1);
        }

        public byte[] RSADecrypt(byte[] data, string privateKeyFile)
        {
            // Load the private RSA key data from a file
            LoadRSAKey(privateKeyFile);

            // Decrypt the data using the RSA object
            return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA1);
        }
    }
}
