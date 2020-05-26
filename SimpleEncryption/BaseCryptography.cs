using System;
using System.Security.Cryptography;

namespace SimpleEncryption
{
    public abstract class BaseCryptography
    {
        public byte[] GenerateRandomNumber(int length)
        {
            using (var randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[length];
                randomNumberGenerator.GetBytes(randomNumber);
                return randomNumber;
            }
        }

        public string GetReadableRandomNumber(byte[] randomNumber)
        {
            return Convert.ToBase64String(randomNumber);
        }

        protected bool Compare(byte[] array1, byte[] array2)
        {
            var result = array1.Length == array2.Length;
            for (var i = 0; i < array1.Length && i < array2.Length; ++i)
            {
                result &= array1[i] == array2[i];
            }

            return result;
        }
        protected bool CompareUnSecure(byte[] array1, byte[] array2)
        {
            if (array1.Length != array2.Length)
            {
                return false;
            }

            for (int i = 0; i < array1.Length; ++i)
            {
                if (array1[i] != array2[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
