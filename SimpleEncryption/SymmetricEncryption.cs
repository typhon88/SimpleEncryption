using System;
using System.IO;
using System.Security.Cryptography;

namespace SimpleEncryption
{
    public class SymmetricEncryption : BaseCryptography, IDisposable
    {
        private bool disposedValue;

        public byte[] Encrypt(byte[] dataToEncrypt, byte[] key, byte[] iv)
        {
            using (var aes = new AesManaged
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7,

                Key = key,
                IV = iv
            })
            using (var memoryStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                cryptoStream.FlushFinalBlock();
                return memoryStream.ToArray();
            }
        }

        public byte[] Decrypt(byte[] dataToDecrypt, byte[] key, byte[] iv)
        {
            using (var aes = new AesManaged()
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7,

                Key = key,
                IV = iv
            })
            using (var memoryStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
                cryptoStream.FlushFinalBlock();
                return memoryStream.ToArray();
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
