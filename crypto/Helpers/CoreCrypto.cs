using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace crypto.Helpers
{
    public class CoreCrypto
    {
        static byte[] saltBytes = { 0x12, 0x18, 0x11, 0x28, 0x99, 0x21, 0x13, 0x39, 0x14, 0x55, 0x88, 0x90, 0x20, 0x59, 0x33, 0x99 };
        static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            // saltBytes = GenerateSalt(8);
            byte[] saltedHashBytes = GenerateSaltedHash(passwordBytes, saltBytes);
            byte[] encryptedBytes = null;
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                     var key = new Rfc2898DeriveBytes(passwordBytes, saltedHashBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }
        static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;
            byte[] saltedHashBytes = GenerateSaltedHash(passwordBytes, saltBytes);
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PaddingMode.None;
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltedHashBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }
        public static void EncryptFile(string inFilePath, string outFilePath, string password, bool delete = false)
        {

            byte[] bytesToBeEncrypted = File.ReadAllBytes(inFilePath);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // Hash the password with SHA256
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);

            File.WriteAllBytes(outFilePath, bytesEncrypted);
            if (delete)
                File.Delete(inFilePath);
        }

        public static void DecryptFile(string inFilePath, string outFilePath, string password, bool delete = false)
        {
            byte[] bytesToBeDecrypted = File.ReadAllBytes(inFilePath);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes);


            File.WriteAllBytes(outFilePath, bytesDecrypted);
            if (delete)
                File.Delete(inFilePath);

        }
        static byte[] GenerateSalt(int n)
        {
            RNGCryptoServiceProvider rncCsp = new RNGCryptoServiceProvider();
            byte[] salt = new byte[n];
            rncCsp.GetBytes(salt);

            return salt;
        }
        static byte[] GenerateSaltedHash(byte[] plainText, byte[] salt)
        {
            HashAlgorithm algorithm = new SHA256Managed();
            byte[] plainTextWithSaltBytes =
              new byte[plainText.Length + salt.Length];

            for (int i = 0; i < plainText.Length; i++)
            {
                plainTextWithSaltBytes[i] = plainText[i];
            }
            for (int i = 0; i < salt.Length; i++)
            {
                plainTextWithSaltBytes[plainText.Length + i] = salt[i];
            }

            return algorithm.ComputeHash(plainTextWithSaltBytes);
        }
    }
}
