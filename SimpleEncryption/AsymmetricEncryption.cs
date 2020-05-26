using System;
using System.Security.Cryptography;

namespace SimpleEncryption
{
    public class AsymmetricEncryption : BaseCryptography, IDisposable
    {
        private bool disposedValue;

        public byte[] EncryptData(byte[] dataToEncrypt, RSAParameters publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(publicKey);
                return rsa.Encrypt(dataToEncrypt, false);
            }
        }

        public byte[] DecryptData(byte[] dataToEncrypt, RSAParameters privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(privateKey);
                return rsa.Decrypt(dataToEncrypt, false);
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

