using NUnit.Framework;
using System.Text;

namespace SimpleEncryption.Tests
{
    [TestFixture]
    public class SymmetricEncryptionTests2
    {
        [SetUp]
        public void Setup() { }

        [Test]
        public void SymmetricEncryption_Test_Pass()
        {
            using (var encryption = new SymmetricEncryption())
            {
                var encryptionKey = encryption.GenerateRandomNumber(32);
                var initializationVector = encryption.GenerateRandomNumber(16);
                const string expected = "Text to encrypt";

                var encrypted = encryption.Encrypt(Encoding.UTF8.GetBytes(expected), encryptionKey, initializationVector);
                var decrypted = encryption.Decrypt(encrypted, encryptionKey, initializationVector);
                string actual = Encoding.UTF8.GetString(decrypted);
                string encryptedAsString = Encoding.UTF8.GetString(encrypted);

                Assert.AreEqual(expected, actual);
                Assert.AreNotEqual(expected, encryptedAsString);
            }
        }

        [Test]
        public void SymmetricEncryption_Test__DifferentIV_Pass()
        {
            using (var encryption = new SymmetricEncryption())
            {
                var encryptionKey = encryption.GenerateRandomNumber(32);
                var initializationVector = encryption.GenerateRandomNumber(16);
                var otherIV = encryption.GenerateRandomNumber(16);

                const string expected = "Text to encrypt";

                var encrypted = encryption.Encrypt(Encoding.UTF8.GetBytes(expected), encryptionKey, initializationVector);
                var decrypted = encryption.Decrypt(encrypted, encryptionKey, otherIV);
                string actual = Encoding.UTF8.GetString(decrypted);


                var ex = Assert.Catch<System.Security.Cryptography.CryptographicException>(() => encryption.Decrypt(encrypted, encryptionKey, otherIV));
                Assert.AreEqual(ex.Message, "System.Security.Cryptography.CryptographicException : Padding is invalid and cannot be removed.");
            }
        }

        [Test]
        public void SymmetricEncryption_Test_DifferentText_Pass()
        {
            using (var encryption = new SymmetricEncryption())
            {
                var encryptionKey = encryption.GenerateRandomNumber(32);
                var initializationVector = encryption.GenerateRandomNumber(16);
                const string original = "Actual text to encrypt";
                const string expected = "Text to compare";

                var encrypted = encryption.Encrypt(Encoding.UTF8.GetBytes(original), encryptionKey, initializationVector);
                var decrypted = encryption.Decrypt(encrypted, encryptionKey, initializationVector);
                string actual = Encoding.UTF8.GetString(decrypted);

                Assert.AreNotEqual(expected, actual);
                Assert.AreEqual(original, actual);
            }
        }
    }
}
