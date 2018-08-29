using System;
using crypto.Helpers;

namespace crypto
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            // CoreDecryption.EncryptFile("f.png", "ff.png", "abcd");
            while (true)
            {
                Console.WriteLine("Encrypt (E) or Decrypt (D) files?");
                var key = Console.Read();
                Console.WriteLine();
                if ((Convert.ToChar(key).Equals('e')) || (Convert.ToChar(key).Equals('E')))
                {
                    try
                    {
                        Console.Write("input path file to be encrypted: ");
                        string inputFile = Console.ReadLine();
                        Console.Write("encrypted output file path: ");
                        string outputFile = Console.ReadLine();
                        Console.Write("password: ");
                        string password = Console.ReadLine();
                        CoreCrypto.EncryptFile(inputFile, outputFile, password);
                        Console.WriteLine("successfully completed\n\n\n");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("error");
                    }

                }
                else if ((Convert.ToChar(key).Equals('d')) || (Convert.ToChar(key).Equals('D')))
                {
                    try
                    {
                        Console.Write("input path file to be decrypted: ");
                        string inputFile = Console.ReadLine();
                        Console.Write("decrypted output file path: ");
                        string outputFile = Console.ReadLine();
                        Console.Write("password: ");
                        string password = Console.ReadLine();
                        CoreCrypto.DecryptFile(inputFile, outputFile, password);
                        Console.WriteLine("successfully completed\n\n\n");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("error");
                    }

                }
                else
                {
                    break;
                }
            }

        }

    }
}
