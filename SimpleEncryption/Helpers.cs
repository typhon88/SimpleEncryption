using System;
using System.Security.Cryptography;
using System.Text;

namespace SimpleEncryption
{
    public class Helpers
    {
        public string ComputeHmacFromString(string toBeHashed, string key)
        {

            return Convert.ToBase64String(Hashing.ComputeHmacSha256(Encoding.UTF8.GetBytes(toBeHashed), Encoding.UTF8.GetBytes(key)));
        }

        public static string HashString(string toBeHashed, bool strongerHash)
        {
            var hashed = strongerHash ? Hashing.ComputeHashSha256(Encoding.UTF8.GetBytes(toBeHashed)) :
                                        Hashing.ComputeHashSha512(Encoding.UTF8.GetBytes(toBeHashed));
            return Convert.ToBase64String(hashed);
        }

        public static string HashPasswordString(string password, string salt)
        {
            return Convert.ToBase64String(Hashing.HashPasswordWithSalt(
              Encoding.UTF8.GetBytes(password),
              Encoding.UTF8.GetBytes(salt)));
        }

        public static string HashPasswordString(string password, string salt, int numberOfDerivations)
        {
            return Convert.ToBase64String(Hashing.HashPasswordWithSaltAndDerivations(
              Encoding.UTF8.GetBytes(password),
              Encoding.UTF8.GetBytes(salt),
              numberOfDerivations));
        }

        public (RSAParameters PublicKey, RSAParameters PrivateKey) GenerateRSAKeys(int keySize = 2048)
        {
            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                rsa.PersistKeyInCsp = false;
                return (rsa.ExportParameters(false), rsa.ExportParameters(true));
            }
        }
    }
}
