using NUnit.Framework;
using System.Security.Cryptography;
using System.Text;

namespace SimpleEncryption.Tests
{
    [TestFixture]

    public class HashTests
    {
        [SetUp]
        public void Setup()
        {

        }

        [Test]
        public void Hash_Test_Pass()
        {
            var document = Encoding.UTF8.GetBytes("Document to Sign");
            byte[] hashedDocument = Hashing.ComputeHashSha256(document);
            string actual = Encoding.UTF8.GetString(hashedDocument);
            Assert.AreNotEqual(document, actual);
        }
    }
}
