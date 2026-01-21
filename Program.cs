using System;
using System.IO;
using System.Security.Cryptography; // Бібліотека для криптографії (AES, SHA256)
using System.Text;

namespace CryptoLab
{
   class Program
   {
      static void Main(string[] args)
      {
         // 1. НАЛАШТУВАННЯ КОНСОЛІ
         // Необхідно для коректного відображення українських літер (кирилиці)
         Console.OutputEncoding = Encoding.UTF8;
         Console.InputEncoding = Encoding.UTF8;

         Console.WriteLine("=== Лабораторна робота: Email-шифратор ===");
         Console.WriteLine("Програма працює циклічно. Для виходу оберіть відповідний пункт.\n");

         // 2. ГОЛОВНИЙ ЦИКЛ ПРОГРАМИ
         // while(true) дозволяє виконувати операції багаторазово без перезапуску програми
         while (true)
         {
            Console.WriteLine("------------------------------------------------");
            Console.WriteLine("Оберіть дію:");
            Console.WriteLine("1. ЗАШИФРУВАТИ повідомлення");
            Console.WriteLine("2. РОЗШИФРУВАТИ повідомлення");
            Console.WriteLine("3. Вихід");
            Console.Write("Ваш вибір (1-3): ");

            string choice = Console.ReadLine();

            // Обробка вибору користувача
            switch (choice)
            {
               case "1":
                  PerformEncryption(); // Виклик методу шифрування
                  break;
               case "2":
                  PerformDecryption(); // Виклик методу розшифрування
                  break;
               case "3":
                  return; // Завершення роботи програми
               default:
                  Console.WriteLine("Невірний вибір. Спробуйте ще раз.");
                  break;
            }

            Console.WriteLine("\nНатисніть Enter, щоб продовжити...");
            Console.ReadLine();
         }
      }

      // --- ЛОГІКА ІНТЕРФЕЙСУ ---

      static void PerformEncryption()
      {
         Console.WriteLine("\n--- РЕЖИМ ШИФРУВАННЯ ---");

         // Запитуємо пароль, який стане основою для ключа
         Console.Write("Введіть персональні дані для ключа (напр. IvanPetrenko1995): ");
         string keyData = Console.ReadLine();

         if (string.IsNullOrWhiteSpace(keyData))
         {
            Console.WriteLine("Помилка: Ключ не може бути порожнім!");
            return;
         }

         Console.Write("Введіть текст повідомлення: ");
         string message = Console.ReadLine();

         // КРОК 1: Генерація 32-байтового ключа з пароля
         byte[] key = GenerateKeyFromPassword(keyData);

         // КРОК 2: Шифрування повідомлення цим ключем
         string encryptedText = EncryptString(message, key);

         Console.WriteLine("\nУСПІШНО! Скопіюйте зашифрований рядок нижче:");
         Console.WriteLine("**************************************************");
         Console.WriteLine(encryptedText); // Вивід Base64 рядка
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
            // Генеруємо той самий ключ із того ж самого пароля
            byte[] key = GenerateKeyFromPassword(keyData);

            // Спроба розшифрувати
            string decryptedText = DecryptString(encryptedText, key);

            Console.WriteLine("\nУСПІШНО! Розшифроване повідомлення:");
            Console.WriteLine(">>> " + decryptedText);
         }
         catch (FormatException)
         {
            // Якщо користувач вставив не Base64 рядок
            Console.WriteLine("\nПОМИЛКА: Невірний формат зашифрованого рядка.");
         }
         catch (CryptographicException)
         {
            // Якщо пароль невірний або дані пошкоджені (Padding error)
            Console.WriteLine("\nПОМИЛКА: Невірний ключ (пароль) або пошкоджені дані.");
         }
         catch (Exception ex)
         {
            Console.WriteLine($"\nПОМИЛКА: {ex.Message}");
         }
      }

      // --- КРИПТОГРАФІЧНЕ ЯДРО ---

      /// <summary>
      /// Перетворює довільний текстовий пароль у фіксований ключ довжиною 32 байти (256 біт).
      /// </summary>
      public static byte[] GenerateKeyFromPassword(string password)
      {
         // Використовуємо SHA256, бо він завжди повертає хеш довжиною 256 біт,
         // що ідеально підходить для ключа AES-256.
         using (var sha256 = SHA256.Create())
         {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
         }
      }

      /// <summary>
      /// Шифрує рядок алгоритмом AES.
      /// </summary>
      public static string EncryptString(string plainText, byte[] key)
      {
         // Створюємо об'єкт AES (Advanced Encryption Standard)
         using (Aes aesAlg = Aes.Create())
         {
            aesAlg.Key = key; // Встановлюємо наш секретний ключ

            // ВАЖЛИВО: Генеруємо новий випадковий вектор ініціалізації (IV).
            // Це робить шифрування унікальним навіть для однакових повідомлень.
            aesAlg.GenerateIV();
            byte[] iv = aesAlg.IV;

            // Створюємо шифратор (ICryptoTransform)
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // MemoryStream - це буфер в пам'яті, куди буде записуватися результат
            using (MemoryStream msEncrypt = new MemoryStream())
            {
               // СПОЧАТКУ записуємо IV (перші 16 байт). Він не є секретним,
               // але потрібен для розшифрування.
               msEncrypt.Write(iv, 0, iv.Length);

               // CryptoStream - це "прошарок", який шифрує дані на льоту при запису
               using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
               {
                  // StreamWriter дозволяє зручно писати рядки в потік
                  using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                  {
                     swEncrypt.Write(plainText); // Записуємо саме повідомлення
                  }
               }

               // Результат (IV + Шифротекст) конвертуємо в Base64,
               // щоб його можна було передати як звичайний текст.
               return Convert.ToBase64String(msEncrypt.ToArray());
            }
         }
      }

      /// <summary>
      /// Розшифровує рядок алгоритмом AES.
      /// </summary>
      public static string DecryptString(string cipherText, byte[] key)
      {
         // Конвертуємо Base64 назад у масив байтів
         byte[] fullCipher = Convert.FromBase64String(cipherText);

         using (Aes aesAlg = Aes.Create())
         {
            aesAlg.Key = key;

            // Створюємо масив для IV (стандартний блок AES - 16 байт)
            byte[] iv = new byte[16];

            // Витягуємо перші 16 байт із отриманих даних - це наш IV
            Array.Copy(fullCipher, 0, iv, 0, iv.Length);
            aesAlg.IV = iv; // Встановлюємо IV в алгоритм

            // Створюємо дешифратор
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Створюємо потік для читання даних, пропускаючи перші 16 байт (бо це IV)
            using (MemoryStream msDecrypt = new MemoryStream(fullCipher, iv.Length, fullCipher.Length - iv.Length))
            {
               // CryptoStream у режимі Read розшифровує дані при їх зчитуванні
               using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
               {
                  using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                  {
                     // Читаємо розшифрований текст повністю
                     return srDecrypt.ReadToEnd();
                  }
               }
            }
         }
      }
   }
}