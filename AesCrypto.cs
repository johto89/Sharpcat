using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SvcUtil
{
    internal static class AesCrypto
    {
        /// <summary>Encrypt plaintext bytes. Returns IV + ciphertext.</summary>
        public static byte[] Encrypt(byte[] plaintext, string password)
        {
            byte[] key = DeriveKey(password);
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.GenerateIV();

                using (var enc = aes.CreateEncryptor())
                {
                    byte[] cipher = enc.TransformFinalBlock(
                        plaintext, 0, plaintext.Length);

                    // Prepend IV so decryptor can extract it
                    byte[] result = new byte[16 + cipher.Length];
                    Buffer.BlockCopy(aes.IV, 0, result, 0, 16);
                    Buffer.BlockCopy(cipher, 0, result, 16, cipher.Length);
                    return result;
                }
            }
        }

        /// <summary>Decrypt data produced by Encrypt().</summary>
        public static byte[] Decrypt(byte[] data, string password)
        {
            if (data == null || data.Length < 17)
                throw new ArgumentException("Invalid encrypted data");

            byte[] key = DeriveKey(password);
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                byte[] iv = new byte[16];
                Buffer.BlockCopy(data, 0, iv, 0, 16);
                aes.IV = iv;

                using (var dec = aes.CreateDecryptor())
                {
                    return dec.TransformFinalBlock(data, 16, data.Length - 16);
                }
            }
        }

        /// <summary>Encrypt → base64 string (for embedding in source).</summary>
        public static string EncryptToBase64(byte[] data, string password)
        {
            return Convert.ToBase64String(Encrypt(data, password));
        }

        /// <summary>Base64 → decrypt (runtime payload recovery).</summary>
        public static byte[] DecryptFromBase64(string base64, string password)
        {
            return Decrypt(Convert.FromBase64String(base64), password);
        }

        private static byte[] DeriveKey(string password)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }
    }
}
