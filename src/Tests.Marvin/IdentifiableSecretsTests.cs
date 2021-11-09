using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Text;

namespace Microsoft.Security.Utilities
{
    [TestClass]
    public class IdentifiableSecretsTests
    {
        private const string Seed = "DEFAULT0";
        private const string Signature = "+Sig";

        [TestMethod]
        public void IdentifiableSecrets_GenerateIdentifiableKey_ShouldThrowExceptionWhenLengthIsInvalid()
        {
            ulong seed = BitConverter.ToUInt64(Encoding.ASCII.GetBytes(Seed).Reverse().ToArray(), 0);

            Assert.ThrowsException<ArgumentException>(() =>
                IdentifiableSecrets.GenerateIdentifiableKey(seed,
                                                            keyLengthInBytes: IdentifiableSecrets.MaximumGeneratedKeySize + 1,
                                                            base64EncodedSignature: Signature));

            Assert.ThrowsException<ArgumentException>(() =>
                IdentifiableSecrets.GenerateIdentifiableKey(seed,
                                                            keyLengthInBytes: IdentifiableSecrets.MinimumGeneratedKeySize - 1,
                                                            base64EncodedSignature: Signature));

            Assert.ThrowsException<ArgumentException>(() =>
                IdentifiableSecrets.GenerateIdentifiableKey(seed,
                                                            keyLengthInBytes: 32,
                                                            base64EncodedSignature: null));

            Assert.ThrowsException<ArgumentException>(() =>
                IdentifiableSecrets.GenerateIdentifiableKey(seed,
                                                            keyLengthInBytes: 32,
                                                            base64EncodedSignature: "bad-signature-length"));
        }

        [TestMethod]
        public void IdentifiableSecrets_ValidateKey_ShouldReturnFalseIfSecretIsInvalid()
        {
            const int size = 32;
            ulong seed = BitConverter.ToUInt64(Encoding.ASCII.GetBytes(Seed).Reverse().ToArray(), 0);

            string secret = IdentifiableSecrets.GenerateIdentifiableKey(seed,
                                                                        keyLengthInBytes: size,
                                                                        base64EncodedSignature: Signature);

            string newSignature = Signature.ToLowerInvariant();
            Assert.AreNotEqual(Signature, newSignature);

            string newSecret = secret.Replace(Signature, newSignature);
            var isValid = IdentifiableSecrets.ValidateKey(newSecret, seed, Signature);
            Assert.IsFalse(isValid);

            newSecret = secret.Remove(secret.Length - 2, 1).Insert(secret.Length - 2, "+");
            isValid = IdentifiableSecrets.ValidateKey(newSecret, seed, Signature);
            Assert.IsFalse(isValid);
        }

        [TestMethod]
        public void IdentifiableSecrets_GenerateIdentifiableKey_ShouldBeValidKey()
        {
            ulong seed = BitConverter.ToUInt64(Encoding.ASCII.GetBytes(Seed).Reverse().ToArray(), 0);

            var sizes = new uint[]
            {
                IdentifiableSecrets.MinimumGeneratedKeySize,
                IdentifiableSecrets.MaximumGeneratedKeySize,
                63, 64, 65, 66
            };

            foreach (uint size in sizes)
            {
                string secret = IdentifiableSecrets.GenerateIdentifiableKey(seed, keyLengthInBytes: size, base64EncodedSignature: Signature);

                var isValid = IdentifiableSecrets.ValidateKey(secret, seed, Signature);
                Assert.IsTrue(isValid);
            }
        }
    }
}
