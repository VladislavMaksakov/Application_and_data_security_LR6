using System.Security.Cryptography;
using System.Text;

namespace CryptoLab
{
   class Program
   {
      static void Main(string[] args)
      {
         Console.OutputEncoding = Encoding.UTF8;
         Console.InputEncoding = Encoding.UTF8;
         Console.WriteLine("=== Лабораторна робота: Email-шифратор ===");
         Console.WriteLine("Програма працює циклічно. Для виходу оберіть відповідний пункт.\n");

         while (true)
         {
            Console.WriteLine("------------------------------------------------");
            Console.WriteLine("Оберіть дію:");
            Console.WriteLine("1. ЗАШИФРУВАТИ повідомлення");
            Console.WriteLine("2. РОЗШИФРУВАТИ повідомлення");
            Console.WriteLine("3. Вихід");
            Console.Write("Ваш вибір (1-3): ");
            string choice = Console.ReadLine();
            switch (choice)
            {
               case "1":
                  PerformEncryption();
                  break;
               case "2":
                  PerformDecryption();
                  break;
               case "3":
                  return;
               default:
                  Console.WriteLine("Невірний вибір. Спробуйте ще раз.");
                  break;
            }

            Console.WriteLine("\nНатисніть Enter, щоб продовжити...");
            Console.ReadLine();
         }
      }
      static void PerformEncryption()
      {
         Console.WriteLine("\n--- РЕЖИМ ШИФРУВАННЯ ---");
         Console.Write("Введіть персональні дані для ключа (напр. IvanPetrenko1995): ");
         string keyData = Console.ReadLine();
         if (string.IsNullOrWhiteSpace(keyData))
         {
            Console.WriteLine("Помилка: Ключ не може бути порожнім!");
            return;
         }
         Console.Write("Введіть текст повідомлення: ");
         string message = Console.ReadLine();
         byte[] key = GenerateKeyFromPassword(keyData);
         string encryptedText = EncryptString(message, key);
         Console.WriteLine("\nУСПІШНО! Скопіюйте зашифрований рядок нижче:");
         Console.WriteLine("**************************************************");
         Console.WriteLine(encryptedText);
         Console.WriteLine("**************************************************");
      }
      static void PerformDecryption()
      {
         Console.WriteLine("\n--- РЕЖИМ РОЗШИФРУВАННЯ ---");
         Console.Write("Введіть персональні дані для ключа (напр. IvanPetrenko1995): ");
         string keyData = Console.ReadLine();
         Console.Write("Вставте зашифрований рядок (Base64): ");
         string encryptedText = Console.ReadLine();
         try
         {
            byte[] key = GenerateKeyFromPassword(keyData);
            string decryptedText = DecryptString(encryptedText, key);

            Console.WriteLine("\nУСПІШНО! Розшифроване повідомлення:");
            Console.WriteLine(">>> " + decryptedText);
         }
         catch (FormatException)
         {
            Console.WriteLine("\nПОМИЛКА: Невірний формат зашифрованого рядка.");
         }
         catch (CryptographicException)
         {
            Console.WriteLine("\nПОМИЛКА: Невірний ключ (пароль) або пошкоджені дані.");
         }
         catch (Exception ex)
         {
            Console.WriteLine($"\nПОМИЛКА: {ex.Message}");
         }
      }
      public static byte[] GenerateKeyFromPassword(string password)
      {
         using (var sha256 = SHA256.Create())
         {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
         }
      }
      public static string EncryptString(string plainText, byte[] key)
      {
         using (Aes aesAlg = Aes.Create())
         {
            aesAlg.Key = key;
            aesAlg.GenerateIV();
            byte[] iv = aesAlg.IV;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
               msEncrypt.Write(iv, 0, iv.Length);
               using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
               {
                  using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                  {
                     swEncrypt.Write(plainText);
                  }
               }
               return Convert.ToBase64String(msEncrypt.ToArray());
            }
         }
      }
      public static string DecryptString(string cipherText, byte[] key)
      {
         byte[] fullCipher = Convert.FromBase64String(cipherText);

         using (Aes aesAlg = Aes.Create())
         {
            aesAlg.Key = key;
            byte[] iv = new byte[16];
            Array.Copy(fullCipher, 0, iv, 0, iv.Length);
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(fullCipher, iv.Length, fullCipher.Length - iv.Length))
            {
               using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
               {
                  using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                  {
                     return srDecrypt.ReadToEnd();
                  }
               }
            }
         }
      }
   }
}