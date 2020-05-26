using System;
using System.Security.Cryptography;

namespace SimpleEncryption
{
    public class HybridEncryption : BaseCryptography, IDisposable
    {
        private readonly AsymmetricEncryption _rsaEncryption;
        private readonly SymmetricEncryption _aesEncryption;
        private readonly DigitalSignature _signature;
        private bool disposedValue;

        public HybridEncryption()
        {
            _rsaEncryption = new AsymmetricEncryption();
            _aesEncryption = new SymmetricEncryption();
            _signature = new DigitalSignature();
        }

        public EncryptedPacket EncryptData(byte[] original, RSAParameters publicEncryptionKey, RSAParameters privateSigningKey)
        {
            var sessionKey = GenerateRandomNumber(32);
            var vector = GenerateRandomNumber(16);
            var encryptedPacket = new EncryptedPacket
            {
                Iv = vector,
                EncryptedData = _aesEncryption.Encrypt(original, sessionKey, vector),
                EncryptedSessionKey = _rsaEncryption.EncryptData(sessionKey, publicEncryptionKey)
            };

            using (var hmac = new HMACSHA256(sessionKey))
            {
                encryptedPacket.Hmac = hmac.ComputeHash(encryptedPacket.EncryptedData);
            }

            encryptedPacket.Signature = _signature.SignData(encryptedPacket.Hmac, privateSigningKey);

            return encryptedPacket;
        }

        public byte[] DecryptData(EncryptedPacket encryptedPacket, RSAParameters privateEncryptionKey, RSAParameters publicSigningKey)
        {
            var decryptedSessionKey = _rsaEncryption.DecryptData(encryptedPacket.EncryptedSessionKey, privateEncryptionKey);

            using (var hmac = new HMACSHA256(decryptedSessionKey))
            {
                var hmacToCheck = hmac.ComputeHash(encryptedPacket.EncryptedData);

                if (!Compare(encryptedPacket.Hmac, hmacToCheck))
                {
                    throw new CryptographicException(
                        "HMAC for decryption does not match encrypted packet.");
                }

                if (!_signature.VerifySignature(encryptedPacket.Hmac, encryptedPacket.Signature, publicSigningKey))
                {
                    throw new CryptographicException(
                        "Digital Signature can not be verified.");
                }
            }

            return _aesEncryption.Decrypt(encryptedPacket.EncryptedData,
                                             decryptedSessionKey,
                                             encryptedPacket.Iv);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _rsaEncryption.Dispose();
                    _aesEncryption.Dispose();
                    _signature.Dispose();
                }
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
