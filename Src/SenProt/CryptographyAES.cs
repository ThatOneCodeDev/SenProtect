using System.Security.Cryptography;

namespace SenProt
{
    /// <summary>
    /// Represents a loaded AES key, including the key, Initialization Vector (IV), and salt.
    /// </summary>
    public class LoadedKey
    {
        /// <summary>
        /// Gets or sets the AES key.
        /// </summary>
        public byte[]? Key { get; set; }

        /// <summary>
        /// Gets or sets the Initialization Vector (IV) for the AES encryption.
        /// </summary>
        public byte[]? IV { get; set; }

        /// <summary>
        /// Gets or sets the salt for the AES key.
        /// </summary>
        public byte[]? Salt { get; set; }
    }

    /// <summary>
    /// A static class that provides AES encryption and decryption methods that adhere to FIPS 140-3.
    /// </summary>
    public static class CryptographyAES
    {

        /// <summary>
        /// Encrypts the plain data using the specified AES key.
        /// </summary>
        /// <param name="plainData">The plain data to encrypt.</param>
        /// <param name="key">The AES key to use for encryption.</param>
        /// <returns>The encrypted data.</returns>
        public static byte[] AESEncrypt(byte[] plainData, LoadedKey key)
        {
            // Ensure that the plain data and key are not null
            if (plainData == null || plainData.Length <= 0)
                throw new ArgumentNullException(nameof(plainData));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Key == null || key.Key.Length <= 0)
                throw new ArgumentNullException(nameof(key.Key));
            if (key.IV == null || key.IV.Length <= 0)
                throw new ArgumentNullException(nameof(key.IV));
            if (key.Salt == null || key.Salt.Length <= 0)
                throw new ArgumentNullException(nameof(key.Salt));

            // Remove the salt from the loaded key
            byte[] saltedKey = new byte[key.Key.Length - key.Salt.Length];
            Array.Copy(key.Key, 0, saltedKey, 0, saltedKey.Length);

            // Create a new AES algorithm
            using Aes aes = Aes.Create();
            // Set the key size to 256 bits
            aes.KeySize = 256;

            // Set the key, IV, padding, and cipher mode for the AES algorithm
            aes.Key = saltedKey;
            aes.IV = key.IV;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            // Create an encryptor to encrypt the data
            using ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            // Encrypt the data and return the result
            byte[] encryptedData = encryptor.TransformFinalBlock(plainData, 0, plainData.Length);
            return encryptedData;
        }


        /// <summary>
        /// Decrypts the encrypted data using the specified AES key.
        /// </summary>
        /// <param name="encryptedData">The encrypted data to decrypt.</param>
        /// <param name="key">The AES key to use for decryption.</param>
        /// <returns>The decrypted data.</returns>
        public static byte[] AESDecrypt(byte[] encryptedData, LoadedKey key)
        {
            // Ensure that the encrypted data and key are not null
            if (encryptedData == null || encryptedData.Length <= 0)
                throw new ArgumentNullException(nameof(encryptedData));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Key == null || key.Key.Length <= 0)
                throw new ArgumentNullException(nameof(key.Key));
            if (key.IV == null || key.IV.Length <= 0)
                throw new ArgumentNullException(nameof(key.IV));
            if (key.Salt == null || key.Salt.Length <= 0)
                throw new ArgumentNullException(nameof(key.Salt));

            // Remove the salt from the loaded key
            byte[] saltedKey = new byte[key.Key.Length - key.Salt.Length];
            Array.Copy(key.Key, 0, saltedKey, 0, saltedKey.Length);

            // Create a new AES algorithm
            using Aes aes = Aes.Create();
            // Set the key size to 256 bits
            aes.KeySize = 256;

            // Set the key, IV, padding, and cipher mode for the AES algorithm
            aes.Key = saltedKey;
            aes.IV = key.IV;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            // Create a decryptor to decrypt the data
            using ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            // Decrypt the data and return the result
            byte[] decryptedData = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            return decryptedData;
        }


        /// <summary>
        /// Generates a new AES key and saves it to the specified key file.
        /// </summary>
        /// <param name="keyFile">The path to the key file to save the AES key to.</param>
        /// <param name="keySize">The size of the AES key to generate (defaults to 256 bits).</param>
        /// <returns>The generated AES key.</returns>
        public static LoadedKey GenerateAESKey(string? keyFile, int keySize = 256)
        {
            // Ensure that the key file is not null
            if (keyFile == null)
                throw new ArgumentNullException(nameof(keyFile));

            // Create a new AES algorithm
            using Aes aes = Aes.Create();
            // Set the key size for the AES algorithm
            aes.KeySize = keySize;

            // Generate the AES key and IV
            aes.GenerateKey();
            aes.GenerateIV();

            // Generate a new salt
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            // Create a LoadedKey object to store the key, IV, and salt
            LoadedKey key = new()
            {
                Key = aes.Key,
                IV = aes.IV,
                Salt = salt
            };

            // Write the key, IV, and salt to the key file
            using (MemoryStream ms = new())
            {
                ms.Write(key.Key, 0, key.Key.Length);
                ms.Write(key.IV, 0, key.IV.Length);
                ms.Write(key.Salt, 0, key.Salt.Length);

                File.WriteAllBytes(keyFile, ms.ToArray());
            }

            // Return the LoadedKey object
            return key;
        }

        /// <summary>
        /// Loads an AES key from the specified key file.
        /// </summary>
        /// <param name="keyFile">The path to the key file to load the AES key from.</param>
        /// <returns>The loaded AES key.</returns>
        public static LoadedKey LoadAESKey(string? keyFile)
        {
            // Ensure that the key file exists and is not null
            if (keyFile == null)
                throw new ArgumentNullException(nameof(keyFile));
            if (!File.Exists(keyFile))
                throw new FileNotFoundException("The specified key file could not be found.");

            // Read the contents of the key file
            byte[] keyData = File.ReadAllBytes(keyFile);

            // Create a LoadedKey object to store the key, IV, and salt
            LoadedKey key = new()
            {
                Key = new byte[256 / 8],
                IV = new byte[128 / 8],
                Salt = new byte[16]
            };

            // Copy the key, IV, and salt from the key data into the LoadedKey object
            Array.Copy(keyData, 0, key.Key, 0, key.Key.Length);
            Array.Copy(keyData, key.Key.Length, key.IV, 0, key.IV.Length);
            Array.Copy(keyData, key.Key.Length + key.IV.Length, key.Salt, 0, key.Salt.Length);

            // Return the LoadedKey object
            return key;
        }
    }
}
