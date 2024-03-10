// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using FluentAssertions;
using FluentAssertions.Execution;

using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities
{
    [TestClass, ExcludeFromCodeCoverage]
    public class IdentifiableSecretsTests
    {
        private static Random s_random;
        private static double s_randomSeed;

        static IdentifiableSecretsTests()
        {
            s_randomSeed = DateTime.UtcNow.TimeOfDay.TotalMilliseconds;
            s_random = new Random((int)s_randomSeed);
        }

        private static string s_base62Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

        [TestMethod]
        public void IdentifiableSecrets_CloudAnnotatedSecurityKeys()
        {
            using var assertionScope = new AssertionScope();
            int iterations = 10;
            for (byte i = 0; i < iterations; i++)
            {
                for (short j = 0; j < iterations; i++)
                {
                    for (byte k = 0; k < iterations; i++)
                    {
                        ulong checksumSeed = (ulong)Guid.NewGuid().ToString().GetHashCode();
                        string signature = Guid.NewGuid().ToString("N").Substring(0, 4);
                        string key = IdentifiableSecrets.GenerateCommonAnnotatedKey(checksumSeed, signature, false, default, default, default, default);
                        key.Should().BeNull();
                    }
                }
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_Base62AlphabetRecognized()
        {
            var alphabet = new HashSet<char>(s_base62Alphabet.ToCharArray());
            for (int i = 0; i < 256; i++)
            {
                Assert.AreEqual(alphabet.Contains((char)i), ((char)i).IsBase62EncodingChar());
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_Base64AlphabetRecognized()
        {
            string base64Alphabet = $"{s_base62Alphabet}+/";
            var alphabet = new HashSet<char>(base64Alphabet.ToCharArray());

            for (int i = 0; i < 256; i++)
            {
                Assert.AreEqual(alphabet.Contains((char)i), ((char)i).IsBase64EncodingChar());
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_Base64UrlAlphabetRecognized()
        {
            string base64UrlAlphabet = $"{s_base62Alphabet}-_";
            var alphabet = new HashSet<char>(base64UrlAlphabet.ToCharArray());

            for (int i = 0; i < 256; i++)
            {
                Assert.AreEqual(alphabet.Contains((char)i), ((char)i).IsBase64UrlEncodingChar());
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_GenerateBase64Key_ShouldThrowExceptionForInvalidLengths()
        {        
            const string signature = "ABCD";
            const string seedText = "DEFAULT0";
            ulong seed = BitConverter.ToUInt64(Encoding.ASCII.GetBytes(seedText).Reverse().ToArray(), 0);

            foreach (bool encodeForUrl in new[] { true, false })
            {
                Assert.ThrowsException<ArgumentException>(() =>
                    IdentifiableSecrets.GenerateBase64KeyHelper(seed,
                                                                keyLengthInBytes: IdentifiableSecrets.MaximumGeneratedKeySize + 1,
                                                                signature,
                                                                encodeForUrl));

                Assert.ThrowsException<ArgumentException>(() =>
                    IdentifiableSecrets.GenerateBase64KeyHelper(seed,
                                                                keyLengthInBytes: IdentifiableSecrets.MinimumGeneratedKeySize - 1,
                                                                signature,
                                                                encodeForUrl));

                Assert.ThrowsException<ArgumentException>(() =>
                    IdentifiableSecrets.GenerateBase64KeyHelper(seed,
                                                                keyLengthInBytes: 32,
                                                                base64EncodedSignature: null,
                                                                encodeForUrl));

                Assert.ThrowsException<ArgumentException>(() =>
                    IdentifiableSecrets.GenerateBase64KeyHelper(seed,
                                                                keyLengthInBytes: 32,
                                                                base64EncodedSignature: "this signature is too long",
                                                                encodeForUrl));
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_GenerateBase64Key_ShouldThrowExceptionForInvalidSignatures()
        {
            Console.WriteLine($"The random values in this test were producing using the seed value: {s_randomSeed}");

            ulong seed = (ulong)s_random.Next();
            uint keyLengthInBytes = (uint)s_random.Next((int)IdentifiableSecrets.MinimumGeneratedKeySize, (int)IdentifiableSecrets.MaximumGeneratedKeySize);

            foreach (bool encodeForUrl in new[] { true, false })
            {
                HashSet<char> alphabet = GetBase64Alphabet(encodeForUrl);

                for (int i = 0; i < 256; i++)
                {
                    char injectedChar = (char)i;
                    string signature = $"XXX{injectedChar}";

                    // If the injected character is legal, we'll go ahead and validate everything works as expected.
                    if (alphabet.Contains(injectedChar))
                    {
                        string secret = IdentifiableSecrets.GenerateBase64KeyHelper(seed,
                                                                                    keyLengthInBytes,
                                                                                    signature,
                                                                                    encodeForUrl);

                        ValidateSecret(secret, seed, signature, encodeForUrl);
                        continue;
                    }

                    // All illegal characters in the signature should raise an exception.
                    Assert.ThrowsException<ArgumentException>(() =>
                        IdentifiableSecrets.GenerateBase64KeyHelper(seed,
                                                                    keyLengthInBytes,
                                                                    signature,
                                                                    encodeForUrl));

                }
            }
        }

        [TestMethod]
        [Timeout(1000 * 60 * 5)]
        public void IdentifiableSecrets_GenerateBase64Key_Comprehensive()
        {
            Console.WriteLine($"The random values in this test were producing using the seed value: {s_randomSeed}");

            // Timeouts in this test would generally indicate that the secret 
            // generation code isn't reliably producing keys using the complete
            // alphabet.

            var keyLengthInBytesValues = new uint[]
            {
                IdentifiableSecrets.MinimumGeneratedKeySize, IdentifiableSecrets.MinimumGeneratedKeySize + 1,
                IdentifiableSecrets.MinimumGeneratedKeySize + 2, IdentifiableSecrets.MinimumGeneratedKeySize + 3,
                IdentifiableSecrets.MaximumGeneratedKeySize - 3, IdentifiableSecrets.MaximumGeneratedKeySize - 2,
                IdentifiableSecrets.MaximumGeneratedKeySize - 2, IdentifiableSecrets.MaximumGeneratedKeySize - 1,
                29, 30, 31, 32, 33, 34, 35,
                63, 64, 65, 66, 67, 68, 69,
            };

            foreach (bool encodeForUrl in new[] { true, false })
            {
                foreach (uint keyLengthInBytes in keyLengthInBytesValues)
                {
                    foreach (ulong seed in GenerateSeedsThatIncludeAllBits())
                    {
                        foreach (string signature in GenerateSignaturesThatIncludeFullAlphabet(encodeForUrl))
                        {
                            foreach (string secret in GenerateSecretsThatIncludeFullAlphabet(seed,
                                                                                             keyLengthInBytes,
                                                                                             signature,
                                                                                             encodeForUrl))
                            {
                                ValidateSecret(secret, seed, signature, encodeForUrl);                                
                            }
                        }
                    }
                }
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_RetrievePaddingForBase64EncodedText()
        {
            using var cryptoProvider = new RNGCryptoServiceProvider();

            for (int i = 0; i < 256; i++)
            {
                var randomBytes = new byte[i];
                cryptoProvider.GetBytes(randomBytes);

                string base64Encoded = Convert.ToBase64String(randomBytes);

                // First, we make sure that our helper properly recognizes existing padding on 
                // a base64-encoded strings. Note that this helper assumes that any padding
                // that exists is valid. I.e., is present because it needs to be, is the 
                // appropriate # of characters, etc.
                string reconstructed = base64Encoded;
                reconstructed += IdentifiableSecrets.RetrievePaddingForBase64EncodedText(reconstructed);
                reconstructed.Should().Be(base64Encoded);

                // Now we trim any padding off the base64-encoded text and ensure we can restore it.
                reconstructed = base64Encoded.TrimEnd('=');
                reconstructed += IdentifiableSecrets.RetrievePaddingForBase64EncodedText(reconstructed);
                reconstructed.Should().Be(base64Encoded);
            }
        }

        private enum Base64EncodingKind
        {
            Unknown,
            Standard,
            UrlSafe
        }

        private void ValidateSecret(string secret, ulong seed, string signature, bool encodeForUrl)
        {
            var isValid = IdentifiableSecrets.ValidateBase64Key(secret, seed, signature, encodeForUrl);
            Assert.IsTrue(isValid);

            var base64EncodingKind = Base64EncodingKind.Unknown;

            if (secret.Contains('+') || secret.Contains('/'))
            {
                base64EncodingKind = Base64EncodingKind.Standard;
            }
            else if (secret.Contains('-') || secret.Contains('_'))
            {
                base64EncodingKind = Base64EncodingKind.UrlSafe;
            }

            byte[] apiDecodedBytes = IdentifiableSecrets.ConvertFromBase64String(secret);

            switch (base64EncodingKind)
            {
                case Base64EncodingKind.Standard:
                {
                    byte[] dotNetDecodedBytes = Convert.FromBase64String(secret);
                    VerifyByteArraysAreEqual(apiDecodedBytes, dotNetDecodedBytes);

                    string urlSafeEncoded = Base64UrlEncoder.Encode(dotNetDecodedBytes);
                    string base64Encoded = IdentifiableSecrets.TransformToStandardEncoding(urlSafeEncoded);
                    base64Encoded += IdentifiableSecrets.RetrievePaddingForBase64EncodedText(base64Encoded);

                    base64Encoded.Should().Be(secret);
                    break;
                }
                case Base64EncodingKind.UrlSafe:
                {
                    byte[] azureDecodedBytes = Base64UrlEncoder.DecodeBytes(secret);
                    VerifyByteArraysAreEqual(apiDecodedBytes, azureDecodedBytes);

                    string base64Encoded = Convert.ToBase64String(azureDecodedBytes);
                    string urlSafeEncoded = IdentifiableSecrets.TransformToUrlSafeEncoding(base64Encoded);

                    string padding = IdentifiableSecrets.RetrievePaddingForBase64EncodedText(secret);
                    urlSafeEncoded.Should().Be(secret + padding);
                    break;
                }
                case Base64EncodingKind.Unknown:
                {
                    secret += IdentifiableSecrets.RetrievePaddingForBase64EncodedText(secret);
                    byte[] dotNetDecodedBytes = Convert.FromBase64String(secret);
                    byte[] azureDecodedBytes = Base64UrlEncoder.DecodeBytes(secret);

                    VerifyByteArraysAreEqual(apiDecodedBytes, dotNetDecodedBytes);
                    VerifyByteArraysAreEqual(dotNetDecodedBytes, azureDecodedBytes);

                    string base64Encoded = Convert.ToBase64String(apiDecodedBytes);
                    string urlSafeEncoded = Base64UrlEncoder.Encode(dotNetDecodedBytes);

                    Assert.IsTrue(base64Encoded == secret && 
                                  urlSafeEncoded == secret.TrimEnd('='));
                    break;
                }
            }

            // Next, we validate that modifying the seed, signature or 
            // the generated token data itself ensures validation fails.
            ulong newSeed = ~seed;
            Assert.AreNotEqual(seed, newSeed);
            isValid = IdentifiableSecrets.ValidateBase64Key(secret, newSeed, signature, encodeForUrl);
            Assert.IsFalse(isValid);

            string newSignature = GetReplacementCharacter(signature[0]) + signature.Substring(1);
            Assert.AreNotEqual(signature, newSignature);
            isValid = IdentifiableSecrets.ValidateBase64Key(secret, seed, newSignature, encodeForUrl);
            Assert.IsFalse(isValid);

            string newSecret = GetReplacementCharacter(secret[0]) + secret.Substring(1);
            Assert.AreNotEqual(secret, newSecret);
            isValid = IdentifiableSecrets.ValidateBase64Key(newSecret, seed, signature, encodeForUrl);
            Assert.IsFalse(isValid);
        }

        private void VerifyByteArraysAreEqual(byte[] first, byte[] second)
        {
            Assert.AreEqual(first.Length, second.Length);
            for (int i = 0; i < first.Length; i++)
            {
                Assert.AreEqual(first[i], second[i]);
            }
        }

        IEnumerable<ulong> GenerateSeedsThatIncludeAllBits()
        {
            ulong bitsObserved = 0;

            while (bitsObserved != ulong.MaxValue)
            {
                uint value1 = (uint)s_random.Next(int.MinValue, int.MaxValue);
                uint value2 = (uint)s_random.Next(int.MinValue, int.MaxValue);

                ulong seed = value1 | (ulong)value2 << 32;
                bitsObserved |= seed;
                yield return seed;
            }
        }

        IEnumerable<string> GenerateSignaturesThatIncludeFullAlphabet(bool encodeForUrl)
        {
            // This yield iterator will continue to generate secrets until all
            // 64 characters of the desired encoding has appeared in at least
            // one secret.

            var alphabet = GetBase64Alphabet(encodeForUrl).ToList();

            while (alphabet.Count > 0)
            {
                string signature = GenerateRandomSignature(encodeForUrl, alphabet);

                foreach (char ch in signature) { alphabet.Remove(ch); }
                yield return signature;
            }
        }

        private string GenerateRandomSignature(bool encodeForUrl, IList<char> alphabet)
        {
            int maxValue = alphabet.Count - 1;
            return string.Concat(alphabet[s_random.Next(0, maxValue)],
                                 alphabet[s_random.Next(0, maxValue)],
                                 alphabet[s_random.Next(0, maxValue)],
                                 alphabet[s_random.Next(0, maxValue)]);
        }

        IEnumerable<string> GenerateSecretsThatIncludeFullAlphabet(ulong seed,
                                                                   uint keyLengthInBytes,
                                                                   string signature,
                                                                   bool encodeForUrl)
        {
            // This yield iterator will continue to generate secrets until all
            // 64 characters of the desired encoding has appeared in at least
            // one secret.

            HashSet<char> alphabet = GetBase64Alphabet(encodeForUrl);

            while (alphabet.Count > 0)
            {
                string secret;
                if (!encodeForUrl)
                {
                    secret = IdentifiableSecrets.GenerateStandardBase64Key(seed,
                                                                           keyLengthInBytes,
                                                                           signature);

                    foreach (char ch in secret) { alphabet.Remove(ch); }
                    yield return secret;
                    continue;
                }

                foreach (bool elidePadding in new[] { true, false })
                {
                    secret = IdentifiableSecrets.GenerateUrlSafeBase64Key(seed,
                                                                          keyLengthInBytes,
                                                                          signature,
                                                                          elidePadding);
                    foreach (char ch in secret) { alphabet.Remove(ch); }
                    yield return secret;
                }
            }
        }
        private static HashSet<char> GetBase64Alphabet(bool encodeForUrl)
        {
            var alphabet = new HashSet<char>(new char[] {
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'});

            if (encodeForUrl)
            {
                alphabet.Add('-');
                alphabet.Add('_');
            }
            else
            {
                alphabet.Add('+');
                alphabet.Add('/');
            }

            return alphabet;
        }

        private string GetReplacementCharacter(char ch)
        {
            // Generate a replacement character that works for all possible
            // generated characters in secrets, whether or not they are encoded
            // with the standard or URL-friendly base64 alphabet.

            if (!Char.IsLetter(ch)) { return "x"; }

            return Char.IsUpper(ch)
                ? ch.ToString().ToLowerInvariant()
                : ch.ToString().ToUpperInvariant();
        }
    }
}
