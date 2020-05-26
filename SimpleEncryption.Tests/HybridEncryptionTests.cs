using NUnit.Framework;
using System.Security.Cryptography;
using System.Text;

namespace SimpleEncryption.Tests
{
    [TestFixture]

    public class HybridEncryptionTests
    {
        [SetUp]
        public void Setup() { }

        [Test]
        public void HybridEncryption_Test_Pass()
        {
            const string expected = "Very secret and important information that can not fall into the wrong hands.";

            using (var encryption = new HybridEncryption())
            {
                (RSAParameters, RSAParameters) encryptionKeys = new Helpers().GenerateRSAKeys();
                (RSAParameters, RSAParameters) signingnKeys = new Helpers().GenerateRSAKeys();

                var encryptedBlock = encryption.EncryptData(Encoding.UTF8.GetBytes(expected), encryptionKeys.Item1, signingnKeys.Item2);
                var decrypted = encryption.DecryptData(encryptedBlock, encryptionKeys.Item2, signingnKeys.Item1);
                string actual = Encoding.UTF8.GetString(decrypted);
                string encryptedAsString = Encoding.UTF8.GetString(encryptedBlock.EncryptedData);

                Assert.AreEqual(expected, actual);
                Assert.AreNotEqual(expected, encryptedAsString);
            }
        }

    }
}
