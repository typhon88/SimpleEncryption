using NUnit.Framework;
using System.Security.Cryptography;
using System.Text;

namespace SimpleEncryption.Tests
{
    [TestFixture]
    public class AsymmetricEncryptionTests
    {
        [SetUp]
        public void Setup() { }

        [Test]
        public void AsymmetricEncryption_Test_Pass()
        {
            using (var encryption = new AsymmetricEncryption())
            {
                (RSAParameters, RSAParameters) keys = new Helpers().GenerateRSAKeys();

                const string expected = "Text to encrypt";

                var encrypted = encryption.EncryptData(Encoding.UTF8.GetBytes(expected), keys.Item1);
                var decrypted = encryption.DecryptData(encrypted, keys.Item2);

                string actual = Encoding.UTF8.GetString(decrypted);
                string encryptedAsString = Encoding.UTF8.GetString(encrypted);

                Assert.AreEqual(expected, actual);
                Assert.AreNotEqual(expected, encryptedAsString);
            }
        }

    }
}
