// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using FluentAssertions;
using FluentAssertions.Execution;

using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

#pragma warning disable SYSLIB0023  // 'RNGCryptoServiceProvider' is obsolete.

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
        public void IdentifiableSecrets_IdentifiableSecrets_ComputeCommonAnnotatedHash()
        {
            foreach (bool longForm in new[] { true, false })
            {
                string signature = GetRandomSignature();

                string cask = IdentifiableSecrets.GenerateCommonAnnotatedKey(signature, customerManagedKey: true, null, null, longForm);
                string legacySecret = Convert.ToBase64String(Guid.NewGuid().ToByteArray());

                foreach (string secret in new[] { cask, legacySecret })
                {
                    string message = Guid.NewGuid().ToString();

                    string hash = IdentifiableSecrets.ComputeCommonAnnotatedHash(message,
                                                                                 Convert.FromBase64String(secret),
                                                                                 signature,
                                                                                 customerManagedKey: true,
                                                                                 platformReserved: null,
                                                                                 providerReserved: null,
                                                                                 longForm);
                }
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_GenerateCommonAnnotatedTestKey_WithCustomAllocationTime()
        {
            string signature = GetRandomSignature();

            DateTime allocationTime = new DateTime(2033, 7, 1, 0, 0, 0, DateTimeKind.Utc);

            string key = IdentifiableSecrets.GenerateCommonAnnotatedTestKey(new byte[64],
                                                                            ulong.MaxValue,
                                                                            signature,
                                                                            customerManagedKey: true,
                                                                            platformReserved: new byte[9],
                                                                            providerReserved: new byte[3],
                                                                            longForm: true,
                                                                            'x',
                                                                            '9',
                                                                            allocationTime);

            // Allocation year = 2033. 'A' is 2024, 'B' is 2025, ... 'J' is 2033.
            // Allocation month = 7 (July). 'A' is January, 'B' is February, ... 'G' is July.
            key.Substring(58, 2).Should().Be("JG");
        }

        [TestMethod]
        public void IdentifiableSecrets_GenerateCommonAnnotatedTestKey_WithMaxAllocationTime()
        {
            string signature = GetRandomSignature();

            DateTime allocationTime = new DateTime(2085, 12, 31, 23, 59, 59, 999, DateTimeKind.Utc);

            string key = IdentifiableSecrets.GenerateCommonAnnotatedTestKey(new byte[64],
                                                                            ulong.MaxValue,
                                                                            signature,
                                                                            customerManagedKey: true,
                                                                            platformReserved: new byte[9],
                                                                            providerReserved: new byte[3],
                                                                            longForm: true,
                                                                            'x',
                                                                            '9',
                                                                            allocationTime);

            // Allocation year = 2085. 'A' is 2024, 'B' is 2025, ... '9' is 2085.
            // Allocation month = 12 (December). 'A' is January, 'B' is February, ... 'L' is December.
            key.Substring(58, 2).Should().Be("9L");
        }

        [TestMethod]
        public void IdentifiableSecrets_GenerateCommonAnnotatedTestKey_RejectsNonUtcAllocationTime()
        {
            string signature = GetRandomSignature();

            DateTime allocationTime = new DateTime(2033, 7, 1, 0, 0, 0, DateTimeKind.Unspecified);

            Action action = () => IdentifiableSecrets.GenerateCommonAnnotatedTestKey(new byte[64],
                                                                                     ulong.MaxValue,
                                                                                     signature,
                                                                                     customerManagedKey: true,
                                                                                     platformReserved: new byte[9],
                                                                                     providerReserved: new byte[3],
                                                                                     longForm: true,
                                                                                     'x',
                                                                                     '9',
                                                                                     allocationTime);

            action.Should().Throw<ArgumentException>(because: $"caller is responsible for providing a UTC allocation time, if a specific allocation time is provided");
        }

        [TestMethod]
        public void IdentifiableSecrets_GenerateCommonAnnotatedTestKey_RejectsAllocationTimesBefore2024()
        {
            string signature = GetRandomSignature();

            DateTime allocationTime = new DateTime(2023, 7, 1, 0, 0, 0, DateTimeKind.Utc);

            Action action = () => IdentifiableSecrets.GenerateCommonAnnotatedTestKey(new byte[64],
                                                                                     ulong.MaxValue,
                                                                                     signature,
                                                                                     customerManagedKey: true,
                                                                                     platformReserved: new byte[9],
                                                                                     providerReserved: new byte[3],
                                                                                     longForm: true,
                                                                                     'x',
                                                                                     '9',
                                                                                     allocationTime);

            action.Should().Throw<ArgumentOutOfRangeException>(because: $"this code was not deployed before 2024 meaning allocation must happen in 2024 or later");
        }

        [TestMethod]
        public void IdentifiableSecrets_GenerateCommonAnnotatedTestKey_RejectsAllocationTimesAfter2085()
        {
            string signature = GetRandomSignature();

            DateTime allocationTime = new DateTime(2086, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            Action action = () => IdentifiableSecrets.GenerateCommonAnnotatedTestKey(new byte[64],
                                                                                     ulong.MaxValue,
                                                                                     signature,
                                                                                     customerManagedKey: true,
                                                                                     platformReserved: new byte[9],
                                                                                     providerReserved: new byte[3],
                                                                                     longForm: true,
                                                                                     'x',
                                                                                     '9',
                                                                                     allocationTime);

            action.Should().Throw<ArgumentOutOfRangeException>(because: $"an allocation time after year 2085 is not supported due to base62 out of range");
        }

        [TestMethod]
        public void IdentifiableSecrets_GenerateCommonAnnotatedTestKey()
        {
            string signature = GetRandomSignature();

            byte[] platformReserved = new byte[9];
            byte[] providerReserved = new byte[3];

            Action action = () => IdentifiableSecrets.GenerateCommonAnnotatedTestKey(new byte[64],
                                                                                     ulong.MaxValue,
                                                                                     signature,
                                                                                     customerManagedKey: true,
                                                                                     platformReserved,
                                                                                     providerReserved,
                                                                                     longForm: true,
                                                                                     'x',
                                                                                     '9');

            action.Should().NotThrow<ArgumentException>(because: $"platform and provider byte counts are correct for GenerateCommonAnnotatedTestKey");

            platformReserved = new byte[8];
            action.Should().Throw<ArgumentException>(because: $"platform byte count must be 9 for GenerateCommonAnnotatedTestKey");

            platformReserved = new byte[9];
            providerReserved = new byte[2];
            action.Should().Throw<ArgumentException>(because: $"provider byte count must be 9 for GenerateCommonAnnotatedTestKey");
        }

        [TestMethod]
        public void IdentifiableSecrets_ComputeDerivedIdentifiableKeyThrowsOnInvalidSecret()
        {
            string signature = GetRandomSignature();

            foreach (bool longForm in new[] { true, false })
            {
                string key = Convert.ToBase64String(new byte[64]);
                Action action = () => IdentifiableSecrets.ComputeDerivedCommonAnnotatedKey("NonsensitiveData",
                                                                                           key,
                                                                                           longForm);

                action.Should().Throw<ArgumentException>(because: $"'{key}' is not a valid secret for ComputeDerivedCommonAnnotatedKey");
             
                key = IdentifiableSecrets.GenerateCommonAnnotatedKey(signature, customerManagedKey: true, new byte[9], new byte[3], longForm);

                action.Should().NotThrow<ArgumentException>(because: $"'{key}' is a valid secret for ComputeDerivedCommonAnnotatedKey");

                // Replace a random non-padding char with a different char. Note
                // that replacing a padding char will make the key invalid
                // base64 which is a different error case tested elsewhere.
                int index = s_random.Next() % key.TrimEnd('=').Length;
                char replacement = key[index] == 'X' ? 'Y' : 'X';
                key = $"{key.Substring(0, index)}{replacement}{key.Substring(index + 1)}";
                action.Should().Throw<ArgumentException>(because: $"'{key}' is not a valid secret for ComputeDerivedCommonAnnotatedKey");
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_ComputeDerivedIdentifiableKeyThrowsOnInvalidBase64()
        {
            string[] invalidBase64 = [
                new string('?', (int)IdentifiableSecrets.StandardEncodedCommonAnnotatedKeySize),
                new string('A', (int)IdentifiableSecrets.LongFormEncodedCommonAnnotatedKeySize - 2) + "=X",
            ];

            foreach (string secret in invalidBase64)
            {
                Action action = () => IdentifiableSecrets.ComputeDerivedCommonAnnotatedKey("NonsensitiveData", secret);
                action.Should().Throw<FormatException>(because: $"'{secret}' is not a valid base64 encoded string");
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_ComputeCommonAnnotatedHashRequiresCorrectIdentifiers()
        {
            using var assertionScope = new AssertionScope();

            string signature = GetRandomSignature();

            for (int i = 0; i < CustomAlphabetEncoder.DefaultBase64Alphabet.Length; i++)
            {
                foreach (bool customerManagedKey in new[] { true, false })
                {
                    foreach (bool longForm in new[] { true, false })
                    {
                        char keyKindSignature = CustomAlphabetEncoder.DefaultBase64Alphabet[i];

                        if (keyKindSignature == 'D' || keyKindSignature == 'H')
                        {
                            continue;
                        }

                        Action action = () => IdentifiableSecrets.ComputeCommonAnnotatedHash("NonsensitiveData",
                                                                                             new byte[64],
                                                                                             signature,
                                                                                             customerManagedKey,
                                                                                             new byte[9],
                                                                                             new byte[3],
                                                                                             longForm,
                                                                                             keyKindSignature);

                        action.Should().Throw<ArgumentException>(because: $"'{keyKindSignature}' should not be a valid ComputeCommonAnnotatedHash identifier");

                        action = () => IdentifiableSecrets.ComputeCommonAnnotatedHash("NonsensitiveData",
                                                                                      Convert.ToBase64String(new byte[64]),
                                                                                      longForm, 
                                                                                      keyKindSignature);

                        action.Should().Throw<ArgumentException>(because: $"'{keyKindSignature}' should not be a valid ComputeCommonAnnotatedHash identifier");
                    }
                }
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_TryValidateCommonAnnotatedKeyInvalidLengths()
        {
            using var assertionScope = new AssertionScope();

            string signature = GetRandomSignature();

            bool result = IdentifiableSecrets.TryValidateCommonAnnotatedKey((byte[])null, signature);
            result.Should().BeFalse(because: "null key should not validate in 'TryValidateCommonAnnotatedKey'");

            for (int i = 0; i < 100; i++)
            {
                if (i == IdentifiableSecrets.StandardCommonAnnotatedKeySizeInBytes ||
                    i == IdentifiableSecrets.LongFormCommonAnnotatedKeySizeInBytes)
                {
                    continue;
                }

                result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(new byte[i], signature);
                result.Should().BeFalse(because: $"byte array of invalid length '{i} should not validate in 'TryValidateCommonAnnotatedKey'");
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_TryValidateCommonAnnotatedKeyBase64EncodedChecksums()
        {
            using var assertionScope = new AssertionScope();

            for (int i = 0; i < 1; i++)
            {
                foreach (bool longForm in new[] { true, false })
                {
                    string signature = GetRandomSignature();
                    string key = IdentifiableSecrets.GenerateCommonAnnotatedKey(signature,
                                                                                customerManagedKey: true,
                                                                                new byte[9],
                                                                                new byte[3],
                                                                                longForm);

                    byte[] keyBytes = Convert.FromBase64String(key);

                    ulong checksumSeed = IdentifiableSecrets.VersionTwoChecksumSeed;

                    int firstChecksumByteIndex = CommonAnnotatedKey.ChecksumBytesIndex;
                    byte[] bytesToChecksum = new byte[firstChecksumByteIndex];
                    Array.Copy(keyBytes, bytesToChecksum, bytesToChecksum.Length);

                    int checksum = Marvin.ComputeHash32(bytesToChecksum, checksumSeed, 0, bytesToChecksum.Length);
                    byte[] computedChecksumBytes = BitConverter.GetBytes(checksum);

                    int checksumLength = longForm ? 4 : 3;
                    Array.Copy(computedChecksumBytes, 0, keyBytes, CommonAnnotatedKey.ChecksumBytesIndex, checksumLength);

                    bool result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(keyBytes, signature);
                    result.Should().BeTrue(because: $"{key}' should validate using 'TryValidateCommonAnnotatedKey' with its original checksum");

                    string differentSignature = GetRandomSignature();
                    differentSignature.Should().NotBe(signature, because: "it is random");
                    result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(keyBytes, differentSignature);
                    result.Should().BeFalse(because: $"'{key}' has signature '{signature}', not '{differentSignature}'");

                    CommonAnnotatedKey.TryCreate(key, out CommonAnnotatedKey cask);
                    cask.Should().NotBeNull(because: $"the '{key}' should be a valid cask");

                    byte[] originalChecksum = new byte[cask.ChecksumBytes.Length];
                    Array.Copy(keyBytes, CommonAnnotatedKey.ChecksumBytesIndex, originalChecksum, 0, originalChecksum.Length);

                    for (int j = 0; j < cask.ChecksumBytes.Length; j++)
                    {
                        // Ensure that the we've restored the key entirely
                        Array.Copy(originalChecksum, 0, keyBytes, CommonAnnotatedKey.ChecksumBytesIndex, originalChecksum.Length);
                        result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(keyBytes, signature);
                        result.Should().BeTrue(because: $"{key}' should validate using 'TryValidateCommonAnnotatedKey' with its original checksum");

                        // Now munge a single byte of the checksum and ensure that the key no longer validates.
                        keyBytes[CommonAnnotatedKey.ChecksumBytesIndex + i] = (byte)~keyBytes[CommonAnnotatedKey.ChecksumBytesIndex + i];

                        // Having munged the checksum, the key should no longer validate.
                        result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(keyBytes, signature);
                        result.Should().BeFalse(because: $"{key}' should not validate using 'TryValidateCommonAnnotatedKey' when its checksum is altered");
                    }
                }
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_TryValidateCommonAnnotatedKeyBase62EncodedChecksums()
        {
            using var assertionScope = new AssertionScope();

            for (int i = 0; i < 1; i++)
            {
                foreach (bool longForm in new[] { true, false })
                {
                    string signature = GetRandomSignature();
                    string key = IdentifiableSecrets.GenerateCommonAnnotatedKey(signature,
                                                                                customerManagedKey: true,
                                                                                new byte[9],
                                                                                new byte[3],
                                                                                longForm);

                    byte[] keyBytes = Convert.FromBase64String(key);
                    bool result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(keyBytes, signature);
                    result.Should().BeTrue(because: $"{key}' should validate using 'TryValidateCommonAnnotatedKey' with its original checksum");

                    CommonAnnotatedKey.TryCreate(key, out CommonAnnotatedKey cask);
                    cask.Should().NotBeNull(because: $"the '{key}' should be a valid cask");

                    byte[] originalChecksum = new byte[cask.ChecksumBytes.Length];
                    Array.Copy(keyBytes, CommonAnnotatedKey.ChecksumBytesIndex, originalChecksum, 0, originalChecksum.Length);

                    for (int j = 0; j < cask.ChecksumBytes.Length; j++)
                    {
                        // Ensure that the we've restored the key entirely
                        Array.Copy(originalChecksum, 0, keyBytes, CommonAnnotatedKey.ChecksumBytesIndex, originalChecksum.Length);
                        result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(keyBytes, signature);
                        result.Should().BeTrue(because: $"{key}' should validate using 'TryValidateCommonAnnotatedKey' with its original checksum");

                        // Now munge a single byte of the checksum and ensure that the key no longer validates.
                        keyBytes[CommonAnnotatedKey.ChecksumBytesIndex + i] = (byte)~keyBytes[CommonAnnotatedKey.ChecksumBytesIndex + i];

                        // Having munged the checksum, the key should no longer validate.
                        result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(keyBytes, signature);
                        result.Should().BeFalse(because: $"{key}' should not validate using 'TryValidateCommonAnnotatedKey' when its checksum is altered");
                    }
                }
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_ComputeCommonAnnotatedHashByteArrayOverloadsShouldFunction()
        {
            using var assertionScope = new AssertionScope();

            foreach (bool customerManagedKey in new[] { true, false })
            {
                foreach (bool longForm in new[] { true, false })
                {
                    byte[] commonAnnotatedSecret = Convert.FromBase64String(
                        IdentifiableSecrets.GenerateCommonAnnotatedKey("TEST",
                                                                       customerManagedKey,
                                                                       new byte[9],
                                                                       new byte[3],
                                                                       longForm));

                    string textToHash = "NonsensitiveData";

                    byte[] keyBytes = IdentifiableSecrets.ComputeCommonAnnotatedHash(textToHash, commonAnnotatedSecret);
                    string key = Convert.ToBase64String(keyBytes);

                    bool result = CommonAnnotatedKey.TryCreate(key, out CommonAnnotatedKey caKey);
                    result.Should().BeTrue(because: "the ComputeCommonAnnotatedHash return value should be a valid cask");

                    result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(key, "TEST");
                    result.Should().BeTrue(because: "the ComputeCommonAnnotatedHash return value should validate using 'IdentifiableSecrets.TryValidateCommonAnnotatedKey'");

                    commonAnnotatedSecret = IdentifiableSecrets.GenerateCommonAnnotatedKeyBytes("TEST",
                                                                                                customerManagedKey,
                                                                                                new byte[9],
                                                                                                new byte[3],
                                                                                                longForm);

                    keyBytes = IdentifiableSecrets.ComputeCommonAnnotatedHash(textToHash, commonAnnotatedSecret);
                    key = Convert.ToBase64String(keyBytes);

                    result = CommonAnnotatedKey.TryCreate(key, out caKey);
                    result.Should().BeTrue(because: "the ComputeCommonAnnotatedHash return value should be a valid cask");

                    result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(key, "TEST");
                    result.Should().BeTrue(because: "the ComputeCommonAnnotatedHash return value should validate using 'IdentifiableSecrets.TryValidateCommonAnnotatedKey'");
                }
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_TryValidateCommonAnnotatedKey_GenerateCommonAnnotatedKey_LongForm()
        {
            using var assertionScope = new AssertionScope();

            foreach (bool longForm in new[] { true, false })
            {
                string validSignature = "ABCD";
                string validKey = IdentifiableSecrets.GenerateCommonAnnotatedKey(validSignature,
                                                                                 customerManagedKey: true,
                                                                                 new byte[9],
                                                                                 new byte[3],
                                                                                 longForm: true);

                bool result = TryValidateCommonAnnotatedKeyHelper(validKey, validSignature);
                result.Should().BeTrue(because: $"'{validKey}' should validate.");

                string differentSignature = "WXYZ";
                result = TryValidateCommonAnnotatedKeyHelper(validKey, differentSignature);
                result.Should().BeFalse(because: $"'{validKey}' has signature '{validSignature}', not '{differentSignature}'");

                result = validKey.Length == IdentifiableSecrets.LongFormEncodedCommonAnnotatedKeySize
                    ? validKey.Length == IdentifiableSecrets.LongFormEncodedCommonAnnotatedKeySize
                    : validKey.Length == IdentifiableSecrets.StandardEncodedCommonAnnotatedKeySize;

                result.Should().BeTrue(because: $"'{validKey}' should have correct length with longForm == '{longForm}'");
            }
        }

        private bool TryValidateCommonAnnotatedKeyHelper(string key, string base64EncodedSignature)
        {
            byte[] keyBytes = Convert.FromBase64String(key);
            bool resultFromString = IdentifiableSecrets.TryValidateCommonAnnotatedKey(key, base64EncodedSignature);
            bool resultFromBytes = IdentifiableSecrets.TryValidateCommonAnnotatedKey(keyBytes, base64EncodedSignature);
        
            resultFromBytes.Should().Be(resultFromString, because: 
                $"""
                TryValidate(string, string) and TryValidate(byte[], string) should be equivalent,
                but returned different results for key='{key}', signature='{base64EncodedSignature}':
                  * TryValidate(string, string) -> {resultFromString}
                  * TryValidate(byte[], string) -> {resultFromBytes}{Environment.NewLine}
                """);

            return resultFromString;
        }

        [TestMethod]
        public void IdentifiableSecrets_TryValidateCommonAnnotatedKey_RejectNullEmptyAndWhitespaceArguments()
        {
            using var assertionScope = new AssertionScope();

            string validSignature = "ABCD";
            string validKey = IdentifiableSecrets.GenerateCommonAnnotatedKey(validSignature,
                                                                             customerManagedKey: true,
                                                                             new byte[9],
                                                                             new byte[3]);

            bool result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(validKey, validSignature);
            result.Should().BeTrue(because: $"the generated key {validKey} should validate");

            foreach (string arg in new[] { string.Empty, " ", null })
            {
                result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(key: arg, base64EncodedSignature: validSignature);
                result.Should().BeFalse(because: $"the key '{arg}' is not a valid argument");

                result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(key: validKey, base64EncodedSignature: arg);
                result.Should().BeFalse(because: $"the signature '{arg}' is not a valid argument");
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_TryValidateCommonAnnotatedKey_RejectInvalidSignatures()
        {
            using var assertionScope = new AssertionScope();

            string validSignature = "ABCD";
            string validKey = IdentifiableSecrets.GenerateCommonAnnotatedKey(validSignature,
                                                                             customerManagedKey: true,
                                                                             new byte[9],
                                                                             new byte[3]);

            bool result = TryValidateCommonAnnotatedKeyHelper(validKey, validSignature);
            result.Should().BeTrue(because: "a generated key should validate");

            result = TryValidateCommonAnnotatedKeyHelper(validKey, base64EncodedSignature: "aBcD");
            result.Should().BeFalse(because: "although the signature comparison is case-insentitive, the signature argument must have consistent case");

            foreach (string signature in new[] { "Z", "YY", "XXX", "WWWWW", "1AAA" })
            {
                foreach (bool longForm in new[] { true, false })
                {
                    Action action = () =>
                        IdentifiableSecrets.GenerateCommonAnnotatedKey(signature,
                                                                       customerManagedKey: true,
                                                                       new byte[9],
                                                                       new byte[3],
                                                                       longForm: true);

                    action.Should().Throw<ArgumentException>(because: $"the signature '{signature}' is not valid");

                    result = TryValidateCommonAnnotatedKeyHelper(key: validKey, base64EncodedSignature: signature);
                    result.Should().BeFalse(because: $"'{signature}' is not a valid signature argument");
                }
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_TryValidateCommonAnnotatedKey_RejectInvalidKey()
        {
            using var assertionScope = new AssertionScope();

            string validSignature = "Z123";
            string validKey = IdentifiableSecrets.GenerateCommonAnnotatedKey(validSignature,
                                                                             customerManagedKey: true,
                                                                             new byte[9],
                                                                             new byte[3]);

            bool result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(validKey, validSignature);
            result.Should().BeTrue(because: "a generated key should validate");

            result = IdentifiableSecrets.TryValidateCommonAnnotatedKey($"{validKey}a", validSignature);
            result.Should().BeFalse(because: "a key with an invalid length should not validate");

            result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(validKey.Substring(1), validSignature);
            result.Should().BeFalse(because: "a key with an invalid length should not validate");
        }

        [TestMethod]
        public void IdentifiableSecrets_ValidateCommonAnnotatedKeySignature()
        {
            using var assertionScope = new AssertionScope();

            foreach (string invalidSignature in new[] { "AbAA", "aaaB", "1AAA", "A?AA" })
            {
                var action = () => IdentifiableSecrets.ValidateCommonAnnotatedKeySignature(invalidSignature);
                action.Should().Throw<ArgumentException>(because: $"the signature '{invalidSignature}' is invalid");
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_VariableLengthIdentifiableAndDerivedKeysValidate()
        {
            using var assertionScope = new AssertionScope();

            string textToHash = "NonsensitiveData";

            string shortKey = IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureIotDeviceChecksumSeed,
                                                                            32,
                                                                            IdentifiableMetadata.AzureIotSignature);

            string shortDerivedKey = IdentifiableSecrets.ComputeDerivedIdentifiableKey(textToHash,
                                                                                       shortKey,
                                                                                       IdentifiableMetadata.AzureIotDeviceChecksumSeed);

            string longKey = IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureIotDeviceChecksumSeed,
                                                                           64,
                                                                           IdentifiableMetadata.AzureIotSignature);

            string longDerivedKey = IdentifiableSecrets.ComputeDerivedIdentifiableKey(textToHash,
                                                                                      longKey,
                                                                                      IdentifiableMetadata.AzureIotDeviceChecksumSeed);

            foreach (string key in new[] { shortKey, shortDerivedKey, longKey, longDerivedKey })
            {
                bool result = IdentifiableSecrets.TryValidateBase64Key(key,
                                                                       IdentifiableMetadata.AzureIotDeviceChecksumSeed,
                                                                       IdentifiableMetadata.AzureIotSignature);

                result.Should().BeTrue(because: $"the key '{key}' should be a valid apparent Azure IoT device key");
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_ComputeDerivedCommonAnnotatedKeyOverloadsAreEquivalent()
        {
            string key = IdentifiableSecrets.GenerateCommonAnnotatedKey("ABCD",
                                                                        customerManagedKey: true,
                                                                        new byte[9],
                                                                        new byte[3]);

            string textToHash = "NonsensitiveData";

            byte[] derivedKeyBytes = IdentifiableSecrets.ComputeDerivedCommonAnnotatedKey(textToHash,
                                                                                          Convert.FromBase64String(key));

            string derivedKey = IdentifiableSecrets.ComputeDerivedCommonAnnotatedKey(textToHash, key);

            derivedKey.Should().Be(Convert.ToBase64String(derivedKeyBytes), because: "the computed hash should match the byte array");
        }

        [TestMethod]
        public void IdentifiableSecrets_ComputeCommonAnnotatedHashOverloadsAreEquivalent()
        {
            string key = IdentifiableSecrets.GenerateCommonAnnotatedKey("ABCD",
                                                                        customerManagedKey: true,
                                                                        new byte[9],
                                                                        new byte[3]);

            string textToHash = "NonsensitiveData";

            byte[] computedHashBytes = IdentifiableSecrets.ComputeCommonAnnotatedHash(textToHash,
                                                                                      Convert.FromBase64String(key));

            string computedHash = IdentifiableSecrets.ComputeCommonAnnotatedHash(textToHash, key);

            computedHash.Should().Be(Convert.ToBase64String(computedHashBytes), because: "the computed hash should match the byte array");
        }

        [TestMethod]
        public void IdentifiableSecret_ComputeCommonAnnotatedHashFullOverload()
        {
            string key = IdentifiableSecrets.GenerateCommonAnnotatedKey("ABCD",
                                                                        customerManagedKey: true,
                                                                        new byte[9],
                                                                        new byte[3]);

            string textToHash = "NonsensitiveData";

            byte[] secretBytes = Encoding.UTF8.GetBytes(textToHash);

            IdentifiableSecrets.ComputeCommonAnnotatedHash(textToHash,
                                                           secretBytes,
                                                           "TEST",
                                                           customerManagedKey: true,
                                                           new byte[9], 
                                                           new byte[3],
                                                           longForm: false,
                                                           keyKindSignature: 'D');
        }

        [TestMethod]
        public void IdentifiableSecrets_GeneratedDerivedAndHashedAnnotatedKeys()
        {
            using var assertionScope = new AssertionScope();

            for (int i = 0; i < 16; i++)
            {
                char ch = (char)('A' + i);
                string signature = new string(ch, 4);

                foreach (bool customerManaged in new[] { true, false })
                {
                    string platformEncoded = new string((char)('A' + i + 1), 12);
                    string providerEncoded = new string((char)('A' + i + 2), 4);

                    byte[] platformReserved = Convert.FromBase64String(platformEncoded);
                    byte[] providerReserved = Convert.FromBase64String(providerEncoded);

                    string key = IdentifiableSecrets.GenerateCommonAnnotatedKey(signature,
                                                                                customerManaged,
                                                                                platformReserved,
                                                                                providerReserved);

                    string textToHash = new string((char)('A' + i + 2), 32);

                    foreach (bool derived in new[] { true, false })
                    {
                        foreach (bool longForm in new[] { true, false })
                        {
                            string computedKey = derived
                                ? IdentifiableSecrets.ComputeDerivedCommonAnnotatedKey(textToHash, key, longForm)
                                : IdentifiableSecrets.ComputeCommonAnnotatedHash(textToHash, key, longForm);

                            string label = derived ? "derived" : "hashed";

                            bool result = CommonAnnotatedKey.TryCreate(computedKey, out CommonAnnotatedKey caKey);
                            result.Should().BeTrue(because: $"the derived key '{computedKey}' should be a valid common annotated security key");

                            bool keyKindCorrect = derived ? caKey.IsDerivedKey : caKey.IsHashedDataKey;
                            keyKindCorrect &= derived ? !caKey.IsHashedDataKey : !caKey.IsDerivedKey;

                            keyKindCorrect.Should().BeTrue(because: $"the {label} key '{computedKey}' 'IsDerivedKey' and 'IsHashedDataKey' properties should be correct");

                            caKey.PlatformReserved.Should().Be(platformEncoded, because: "encoded platform reserved data should match");
                            caKey.ProviderReserved.Should().Be(providerEncoded, because: "encoded provider reserved data should match");

                            string expectedSignature = derived ? IdentifiableSecrets.CommonAnnotatedDerivedKeySignature : IdentifiableSecrets.CommonAnnotatedHashedDataSignature;
                            caKey.StandardFixedSignature.Should().Be(expectedSignature);

                            result = IdentifiableSecrets.CommonAnnotatedKeyRegex.IsMatch(computedKey);
                            result.Should().BeTrue(because: $"the {label} key '{computedKey}' should match the canonical format regex");

                            DateTime utcNow = DateTime.UtcNow;
                            caKey.CreationDate.Year.Should().Be(utcNow.Year, because: $"the {label} key creation year should be correct");
                            caKey.CreationDate.Month.Should().Be(utcNow.Month, because: $"the {label} key creation month should be correct");

                            int length = longForm ? 88 : 84;
                            result = computedKey.Length == length;
                            result.Should().BeTrue(because: $"the {label} key '{computedKey}' length should be {length} when 'longForm' == '{longForm}'");
                        }
                    }
                }
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_ComputeChecksumSeed_EnforcesLengthRequirement()
        {
            using var assertionScope = new AssertionScope();

            for (int i = 0; i < 16; i++)
            {
                string literal = $"{new string('A', i)}0";
                Action action = () => IdentifiableSecrets.ComputeHisV1ChecksumSeed(literal);
                if (i == 7)
                {
                    action.Should().NotThrow(because: $"literal '{literal}' should generate a valid seed");
                }
                else
                {
                    action.Should().Throw<ArgumentException>(because: $"literal '{literal}' should raise an exception as it's not the correct length");
                }
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_ComputeChecksumSeed_EnforcesNumericSuffix()
        {
            string literal = $"{new string('A', 8)}";
            Action action = () => IdentifiableSecrets.ComputeHisV1ChecksumSeed(literal);
            action.Should().Throw<ArgumentException>(because: $"literal '{literal}' should raise an exception as it has no trailing number");

            for (int i = 0; i < 10; i++)
            {
                literal = $"{new string('A', 7)}{i}";
                action.Should().NotThrow(because: $"literal '{literal}' should generate a valid seed");
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_ComputeChecksumSeed()
        {
            using var assertionScope = new AssertionScope();

            var tests = new (string literal, ulong seed)[]
            {
                ("ROSeed00", 0x524f536565643030),
                ("RWSeed00", 0x5257536565643030)
            };

            foreach (var test in tests)
            {
                IdentifiableSecrets.ComputeHisV1ChecksumSeed(test.literal).Should().Be(test.seed);
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_DerivedSymmetricKeys()
        {
            using var assertionScope = new AssertionScope();

            foreach (RegexPattern pattern in WellKnownRegexPatterns.HighConfidenceMicrosoftSecurityModels)
            {
                if (!pattern.DetectionMetadata.HasFlag(DetectionMetadata.Identifiable))
                {
                    continue;
                }

                foreach (string example in pattern.GenerateTruePositiveExamples())
                {
                    IIdentifiableKey identifiablePattern = pattern as IIdentifiableKey;
                    if (identifiablePattern == null) { continue; }

                    bool matched = false;

                    foreach (ulong checksumSeed in identifiablePattern.ChecksumSeeds)
                    {
                        foreach (string signature in identifiablePattern.Signatures)
                        {
                            string standaloneSecret =
                                CachedDotNetRegex.Instance.Matches(example,
                                                                   pattern.Pattern,
                                                                   captureGroup: "refine").First().Value;

                            if (IdentifiableSecrets.TryValidateBase64Key(standaloneSecret, checksumSeed, signature, identifiablePattern.EncodeForUrl))
                            {
                                matched = true;
                                string textToSign = $"{Guid.NewGuid()}";

                                foreach (ulong derivedChecksumSeed in new[] { checksumSeed, ~checksumSeed })
                                {
                                    string derivedKey = IdentifiableSecrets.ComputeDerivedIdentifiableKey(textToSign, standaloneSecret, checksumSeed, derivedChecksumSeed, identifiablePattern.EncodeForUrl);
                                    bool isValid = IdentifiableSecrets.TryValidateBase64Key(derivedKey, derivedChecksumSeed, signature);
                                    isValid.Should().BeTrue(because: $"the '{pattern.Name} derived key '{derivedKey}' should validate");

                                    derivedKey.Length.Should().Be(56, because: $"the '{pattern.Name} derived key should be 56 characters long");
                                    derivedKey.Substring(42, 4).Should().Be("deri", because: $"the '{pattern.Name} derived key should contain the 'deri' signature");
                                    derivedKey.Substring(46, 4).Should().Be(signature, because: $"the '{pattern.Name} derived key should contain the '{signature}' signature");
                                }
                            }
                        }
                    }
                    matched.Should().BeTrue(because: $"each {pattern.Name} test pattern should match a documented checksum seed");
                }
            }
        }

        [TestMethod]
        public void IdentifiableSecrets_PlatformAnnotatedSecurityKeys()
        {
            int iterations = 10;
            ulong keysGenerated = 0;
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

            for (byte i = 0; i < iterations; i++)
            {
                for (short j = 0; j < iterations; j++)
                {
                    var signatures = new List<string>();

                    for (byte k = 0; k < iterations; k++)
                    {
                        string signature = Guid.NewGuid().ToString("N").Substring(0, 4);
                        signature = $"{alphabet[(int)keysGenerated % alphabet.Length]}{signature.Substring(1)}";
                        signatures.Add(signature);
                    }

                    Parallel.ForEach(signatures, signature =>
                    {
                        using var assertionScope = new AssertionScope();

                        try
                        {
                            byte[] platformReserved = new byte[9];
                            byte[] providerReserved = new byte[3];

                            int cBits = 28;
                            int pBits = 41;
                            int rBits = 43;
                            int tBits = 45;

                            int? metadata = (cBits << 18) | (cBits << 12) | (cBits << 6) | cBits;
                            byte[] metadataBytes = BitConverter.GetBytes(metadata.Value);

                            platformReserved[0] = metadataBytes[2];
                            platformReserved[1] = metadataBytes[1];
                            platformReserved[2] = metadataBytes[0];

                            metadata = (rBits << 18) | (rBits << 12) | (rBits << 6) | rBits;
                            metadataBytes = BitConverter.GetBytes(metadata.Value);

                            platformReserved[3] = metadataBytes[2];
                            platformReserved[4] = metadataBytes[1];
                            platformReserved[5] = metadataBytes[0];

                            metadata = (tBits << 18) | (tBits << 12) | (tBits << 6) | tBits;
                            metadataBytes = BitConverter.GetBytes(metadata.Value);

                            platformReserved[6] = metadataBytes[2];
                            platformReserved[7] = metadataBytes[1];
                            platformReserved[8] = metadataBytes[0];

                            metadata = (pBits << 18) | (pBits << 12) | (pBits << 6) | pBits;
                            metadataBytes = BitConverter.GetBytes(metadata.Value);

                            providerReserved[0] = metadataBytes[2];
                            providerReserved[1] = metadataBytes[1];
                            providerReserved[2] = metadataBytes[0];

                            foreach (bool customerManaged in new[] { true, false })
                            {
                                foreach (bool longForm in new[] { true, false })
                                {
                                    signature = customerManaged ? signature.ToUpperInvariant() : signature.ToLowerInvariant();

                                    string key = IdentifiableSecrets.GenerateCommonAnnotatedKey(signature,
                                                                                                customerManaged,
                                                                                                platformReserved,
                                                                                                providerReserved,
                                                                                                longForm);

                                    bool result = IdentifiableSecrets.CommonAnnotatedKeyRegex.IsMatch(key);
                                    result.Should().BeTrue(because: $"the key '{key}' should match the common annotated key regex");

                                    result = IdentifiableSecrets.TryValidateCommonAnnotatedKey(key, signature);
                                    result.Should().BeTrue(because: $"the key '{key}' should comprise an HIS v2-conformant pattern");

                                    foreach (bool derived in new[] { true, false })
                                    {
                                        string textToHash = Guid.NewGuid().ToString("N").Substring(0, 32);
                                        string computedKey = derived
                                            ? IdentifiableSecrets.ComputeDerivedCommonAnnotatedKey(textToHash, key, longForm)
                                            : IdentifiableSecrets.ComputeCommonAnnotatedHash(textToHash, key, longForm);

                                        string label = derived ? "derived" : "hashed";

                                        result = CommonAnnotatedKey.TryCreate(computedKey, out CommonAnnotatedKey caKey);
                                        result.Should().BeTrue(because: $"the derived key '{computedKey}' should be a valid common annotated security key");
                                    }

                                    keysGenerated++;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            false.Should().BeTrue(because: $"an unhandled exception occurred: {ex}");
                        }
                    });
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
        public void IdentifiableSecrets_TryValidateBase64Key_ChecksAlphabet()
        {
            using var scope = new AssertionScope();
            bool result;
            ulong seed = 42;
            string signature = "TEST";
            string secretBase64Std = $"83Tv3p0dtmc/cw7eEVxcC7lh6ZM+MgPG3{signature}LBLKt4=";
            string secretBase64Url = $"83Tv3p0dtmc_cw7eEVxcC7lh6ZM-MgPG3{signature}LBLKt4=";

            result = IdentifiableSecrets.TryValidateBase64Key(secretBase64Std, seed, signature, encodeForUrl: false);
            result.Should().Be(true, because: "validation of standard base64 key with encodeForUrl=false should succeed");

            result = IdentifiableSecrets.TryValidateBase64Key(secretBase64Url, seed, signature, encodeForUrl: true);
            result.Should().Be(true, because: "validation of base64url key with encodeForUrl=true should succeed");

            result = IdentifiableSecrets.TryValidateBase64Key(secretBase64Std, seed, signature, encodeForUrl: true);
            result.Should().Be(false, because: "validation of standard base64 key with encodeForUrl=true should fail");

            result = IdentifiableSecrets.TryValidateBase64Key(secretBase64Url, seed, signature, encodeForUrl: false);
            result.Should().Be(false, because: "validation of base64url key with encodeForUrl=false should fail");
        }

        [TestMethod]
        public void IdentifiableSecrets_GenerateBase64Key_ShouldThrowExceptionForInvalidSignatures()
        {
            ulong seed = (ulong)s_random.Next();

            Console.WriteLine($"The random values in this test were producing using the seed value: {seed}");
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

        private static string GetReplacementCharacter(char ch)
        {
            // Generate a replacement character that works for all possible
            // generated characters in secrets, whether or not they are encoded
            // with the standard or URL-friendly base64 alphabet.

            if (!Char.IsLetter(ch)) { return "x"; }

            return Char.IsUpper(ch)
                ? ch.ToString().ToLowerInvariant()
                : ch.ToString().ToUpperInvariant();
        }

        private static string GetRandomSignature()
        {
            byte[] singleByte = new byte[1];
            s_random.NextBytes(singleByte);

            int character = (int)singleByte[0] %26;

            s_random.NextBytes(singleByte);
            bool isUpper = singleByte[0] % 2 == 0;
            
            string signature = $"{s_base62Alphabet[character]}{Guid.NewGuid().ToString("N").Substring(0, 3)}";
            return isUpper ? signature.ToUpperInvariant() : signature.ToLowerInvariant();
        }
    }
}
