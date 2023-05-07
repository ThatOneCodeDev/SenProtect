using System;
using System.Diagnostics;
using System.IO;
using EncryptionLibrary;
using SenProt;

namespace SenProtTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "SenProt - Validation Utility";
            if (Debugger.IsAttached)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("ATTENTION: A debugger is attached to this software, slower encryption and decryption times may be reported than running via Release configuration.");
                Console.WriteLine(Environment.NewLine);
                Console.ResetColor();
            }
            // Test AES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[Validator] Testing AES encryption and decryption...");
            Console.ResetColor();
            Stopwatch stopwatch = Stopwatch.StartNew();
            try
            {
                TestAES();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[Info] AES test result: Success");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[Error] AES test result: Failure");
                Console.WriteLine("[Error] Error message: {0}", ex.Message);
            }
            finally
            {
                Console.ResetColor();
            }
            stopwatch.Stop();
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("[Info] AES test completed in {0}ms", stopwatch.ElapsedMilliseconds);
            Console.ResetColor();

            // Test RSA
            Console.WriteLine(Environment.NewLine);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[Validator] Testing RSA encryption and decryption...");
            Console.ResetColor();
            stopwatch = Stopwatch.StartNew();
            try
            {
                TestRSA();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[Info] RSA test result: Success");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[Error] RSA test result: Failure");
                Console.WriteLine("[Error] Error message: {0}", ex.Message);
            }
            finally
            {
                Console.ResetColor();
            }
            stopwatch.Stop();
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("[Info] RSA test completed in {0}ms", stopwatch.ElapsedMilliseconds);
            Console.ResetColor();

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        static void TestAES()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            // The path to the key file
            string keyFile = "fips140-3.bin";

            // Generate a new AES key and save it to the key file
            Console.WriteLine("[AES-Test: Info] Generating AES key...");
            LoadedKey key = CryptographyAES.GenerateAESKey(keyFile);
            Console.WriteLine("[AES-Test: Info] AES key generated and saved to file.");

            // The plain data to encrypt
            string plainData = "This is the plain data.";
            byte[] plainDataBytes = System.Text.Encoding.UTF8.GetBytes(plainData);

            // Encrypt the plain data using the AES key
            Console.WriteLine("[AES-Test: Info] Encrypting data...");
            byte[] encryptedData = CryptographyAES.AESEncrypt(plainDataBytes, key);
            Console.WriteLine("[AES-Test: Info] Data encrypted.");

            // Load the AES key from the key file
            Console.WriteLine("[AES-Test: Info] Loading AES key...");
            key = CryptographyAES.LoadAESKey(keyFile);
            Console.WriteLine("[AES-Test: Info] AES key loaded.");

            // Decrypt the encrypted data using the AES key
            Console.WriteLine("[AES-Test: Info] Decrypting data...");
            byte[] decryptedData = CryptographyAES.AESDecrypt(encryptedData, key);
            Console.WriteLine("[AES-Test: Info] Data decrypted.");

            // Convert the decrypted data back to a string and print it
            string decryptedDataString = System.Text.Encoding.UTF8.GetString(decryptedData);
            Console.WriteLine("[AES-Test: Info] Decrypted data: " + decryptedDataString);
            Console.ResetColor();
        }

        static void TestRSA()
        {
            // Generate a new RSA key pair and save the public and private keys to separate files
            CryptographyRSA rsa = new();
            CryptographyRSA.GenerateRSAKey("public.xml", "private.xml");

            // Test data to encrypt
            byte[] data = System.Text.Encoding.UTF8.GetBytes("This is a test message");

            // Encrypt the data using the public RSA key
            byte[] encryptedData = rsa.RSAEncrypt(data, "public.xml");

            // Decrypt the encrypted data using the private RSA key
            byte[] decryptedData = rsa.RSADecrypt(encryptedData, "private.xml");

            // Verify that the decrypted data matches the original data
            if (System.Text.Encoding.UTF8.GetString(decryptedData) == System.Text.Encoding.UTF8.GetString(data))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("RSA encryption and decryption test passed!");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("RSA encryption and decryption test failed!");
                Console.ResetColor();
            }

        }

    }
}
