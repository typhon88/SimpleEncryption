using NUnit.Framework;
using System.Security.Cryptography;
using System.Text;

namespace SimpleEncryption.Tests
{
    [TestFixture]
    public class DigitalSignatureTests
    {
        [SetUp]
        public void Setup()
        {

        }

        [Test]
        public void DigitalSignature_Test_Pass()
        {
            var document = Encoding.UTF8.GetBytes("Document to Sign");
            byte[] hashedDocument;

            (RSAParameters, RSAParameters) keys = new Helpers().GenerateRSAKeys();

            using (var sha256 = SHA256.Create())
            {
                hashedDocument = sha256.ComputeHash(document);
            }
            using (var service = new DigitalSignature())
            {
                var signature = service.SignData(hashedDocument, keys.Item2);
                var expected = service.VerifySignature(hashedDocument, signature, keys.Item1);
                Assert.AreEqual(true, expected);
            }
        }

        [Test]
        public void DigitalSignature_Test_Pass_Different_Keys()
        {
            var document = Encoding.UTF8.GetBytes("Document to Sign");
            byte[] hashedDocument;

            (RSAParameters, RSAParameters) keys = new Helpers().GenerateRSAKeys();
            (RSAParameters, RSAParameters) keys2 = new Helpers().GenerateRSAKeys();

            using (var sha256 = SHA256.Create())
            {
                hashedDocument = sha256.ComputeHash(document);
            }
            using (var service = new DigitalSignature())
            {
                var signature = service.SignData(hashedDocument, keys.Item2);
                var expected = service.VerifySignature(hashedDocument, signature, keys2.Item1);
                Assert.AreEqual(false, expected);
            }
        }

        [Test]
        public void DigitalSignature_Test_Pass_Different_Documents()
        {
            var document = Encoding.UTF8.GetBytes("Document to Sign");
            var otherDocument = Encoding.UTF8.GetBytes("Other Document to Sign");

            byte[] hashedDocument;
            byte[] otherHashedDocument;

            (RSAParameters, RSAParameters) keys = new Helpers().GenerateRSAKeys();

            using (var sha256 = SHA256.Create())
            {
                hashedDocument = sha256.ComputeHash(document);
                otherHashedDocument = sha256.ComputeHash(otherDocument);
            }
            using (var service = new DigitalSignature())
            {
                var signature = service.SignData(hashedDocument, keys.Item2);
                var expected = service.VerifySignature(otherHashedDocument, signature, keys.Item1);
                Assert.AreEqual(false, expected);
            }
        }
    }
}