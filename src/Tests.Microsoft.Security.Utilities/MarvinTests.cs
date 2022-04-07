// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Security.Cryptography;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities
{
    [TestClass]
    public class MarvinTests : MarvinShared
    {
#if NET45_OR_GREATER || NETCOREAPP3_1

        /// <summary>
        /// Compare a Marvin checksum against a well-known test case from the native code.
        /// </summary>
        [TestMethod]
        public void MarvinBasic()
        {
            // This test verifies that our C# implementation provides
            // the same result as SymCrypt for their standard test.
            // https://github.com/microsoft/SymCrypt/blob/master/lib/marvin32.c#L316
            ulong seed = 0xd53cd9cecd0893b7;

            string text = "abc";
            byte[] input = Encoding.ASCII.GetBytes(text);

            long expected = 0x22c74339492769bf;

#if NETCOREAPP3_1
            long marvin = Marvin.ComputeHash(input.AsSpan(), seed);
            Assert.AreEqual(expected, marvin);
#elif NET45_OR_GREATER
            long marvin = Marvin.ComputeHash(input, seed, 0, input.Length);
            Assert.AreEqual(expected, marvin);
#endif
        }

        /// <summary>
        /// Compare a Marvin checksum against a well-known test case from the native code.
        /// </summary>
        [TestMethod]
        public void MarvinLongerString()
        {
            // This test verifies that our C# implementation provides
            // the same result as SymCrypt for their standard test.
            // https://github.com/microsoft/SymCrypt/blob/master/lib/marvin32.c#L316
            ulong seed = 0xddddeeeeffff000;

            string text = "abcdefghijklmnopqrstuvwxyz";
            byte[] input = Encoding.ASCII.GetBytes(text);

            long expected = unchecked((long)0xa128eb7e7260aca2);
#if NETCOREAPP3_1
            long marvin = Marvin.ComputeHash(input.AsSpan(), seed);
            Assert.AreEqual(expected, marvin);
#elif NET45_OR_GREATER
            long marvin = Marvin.ComputeHash(input, seed, 0, input.Length);
            Assert.AreEqual(expected, marvin);
#endif
        }

        /// <summary>
        /// Run a set of well-known tests cases that verify Marvin32 behavior.
        /// </summary>
        [TestMethod]
        public void MarvinVariousCases()
        {
            Encoding latin1 = Encoding.GetEncoding("ISO-8859-1");

            foreach (TestCase testCase in TestCases)
            {
                string text = testCase.Text;
                byte[] input = latin1.GetBytes(text);
                ulong seed = testCase.Seed;

                long expected64 = (long)testCase.Checksum;

#if NETCOREAPP3_1
                Span<byte> bytes = input.AsSpan();
                long marvin64 = Marvin.ComputeHash(bytes, seed);
                int expected32 = (int)(marvin64 ^ marvin64 >> 32);
                Assert.AreEqual(expected64, marvin64);

                int marvin32 = Marvin.ComputeHash32(bytes, seed);
                Assert.AreEqual(expected32, marvin32);

                // Validate that our algorithm behavior matches the
                // built-in .NET Marvin32 algorithm encoded in
                // string.GetHashCode(). This code path processes
                // a UTF16 representation of inputs.
                ValidateDotNetStringHashMatchesMarvin(text);
#elif NET45_OR_GREATER
                long marvin64 = Marvin.ComputeHash(input, seed, 0, input.Length);
                int expected32 = (int)(marvin64 ^ marvin64 >> 32);
                Assert.AreEqual(expected64, marvin64);

                int marvin32 = Marvin.ComputeHash32(input, seed, 0, input.Length);
                Assert.AreEqual(expected32, marvin32);
#endif
            }
        }

#if NET45_OR_GREATER

        [TestMethod]
        public void Marvin_ComputeHash_ShouldThrowIfArgumentsAreInvalid()
        {
            var data = new byte[4];
            ulong seed = 0;

            var testCases = new[]
            {
                new
                {
                    Offset = -1,
                    Length = 0
                },
                new
                {
                    Offset = 5,
                    Length = 0
                },
                new
                {
                    Offset = 1,
                    Length = -1
                },
                new
                {
                    Offset = 3,
                    Length = 3
                },
            };

            foreach (var testCase in testCases)
            {
                Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                    Marvin.ComputeHash(data, seed, testCase.Offset, testCase.Length));
            }
        }

#endif

#endif

        /// <summary>
        /// Test partial checksums of input bytes.
        /// </summary>
        [TestMethod]
        public void MarvinLegacyPartialChecksum()
        {
            ulong seed = 0xbeefbeefdeaddead;

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                for (int i = 0; i < 12; i++)
                {
                    int length = i + 1;
                    byte[] buffer = new byte[length + 16];
                    byte[] testData = Encoding.ASCII.GetBytes(new string('+', length));

#if NET45_OR_GREATER
                    int expectedChecksum = Marvin.ComputeHash32(testData, seed, 0, testData.Length);
#else
                    int expectedChecksum = Marvin.ComputeHash32(testData, seed);
#endif

                    for (int j = 0; j < 16; j++)
                    {
                        rng.GetBytes(buffer);
                        testData.CopyTo(buffer, j);

#if NET45_OR_GREATER
                        int actualChecksum = Marvin.ComputeHash32(buffer, seed, j, length);
                        Assert.AreEqual(expectedChecksum, actualChecksum);
#else
                        var testDataSpan = new ReadOnlySpan<byte>(testData);
                        var bufferInternalSpan = new ReadOnlySpan<byte>(buffer, j, length);

#if NETCOREAPP3_1
                        int actualChecksum = Marvin.ComputeHash32(testDataSpan, seed);
                        Assert.AreEqual(expectedChecksum, actualChecksum);

                        actualChecksum = Marvin.ComputeHash32(bufferInternalSpan, seed);
                        Assert.AreEqual(expectedChecksum, actualChecksum);
#else
                        int actualChecksum = Marvin.ComputeHash32(testDataSpan, seed);
                        Assert.AreEqual(expectedChecksum, actualChecksum);

                        actualChecksum = Marvin.ComputeHash32(bufferInternalSpan, seed);
                        Assert.AreEqual(expectedChecksum, actualChecksum);
#endif
#endif
                    }
                }
            }
        }

        /// <summary>
        /// Additional partial checksum tests.
        /// </summary>
        [TestMethod]
        public void MarvinLegacyPartialChecksums()
        {
            ulong seed = 0xdeaddeadbeefbeef;

            int length = 64;
            byte[] buffer = new byte[length];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                Random random = new Random();

                for (int i = 0; i < length; i++)
                {
                    rng.GetBytes(buffer);

                    int testDataLength = random.Next(0, length - i);
                    byte[] testData = Encoding.ASCII.GetBytes(new string('!', testDataLength));
                    testData.CopyTo(buffer, i);
#if NET45_OR_GREATER
                    int expectedChecksum = Marvin.ComputeHash32(testData, seed, 0, testData.Length);

                    int actualChecksum = Marvin.ComputeHash32(buffer, seed, offset: i, testDataLength);

                    Assert.AreEqual(expectedChecksum, actualChecksum);
#else
                    var testDataSpan = new ReadOnlySpan<byte>(testData);
                    var bufferInternalSpan = new ReadOnlySpan<byte>(buffer, i, testDataLength);
                    int expectedChecksum = Marvin.ComputeHash32(testData, seed);

#if NETCOREAPP3_1
                    int actualChecksum = Marvin.ComputeHash32(testDataSpan, seed);
                    Assert.AreEqual(expectedChecksum, actualChecksum);

                    actualChecksum = Marvin.ComputeHash32(bufferInternalSpan, seed);
                    Assert.AreEqual(expectedChecksum, actualChecksum);
#else
                    int actualChecksum = Marvin.ComputeHash32(testDataSpan, seed);
                    Assert.AreEqual(expectedChecksum, actualChecksum);

                    actualChecksum = Marvin.ComputeHash32(bufferInternalSpan, seed);
                    Assert.AreEqual(expectedChecksum, actualChecksum);
#endif
#endif
                }
            }
        }

#if !NET45_OR_GREATER
        /// <summary>
        /// Ensure that the Marvin checksum matches the .NET behavior. This test
        /// will only execute in cases where Marvin itself is implemented as
        /// managed code. Early versions of .NET effectively pinvoke to mscorlib
        /// for this functionality.
        /// </summary>
        [TestMethod]
        public void MarvinMatchesDotNetBehavior()
        {
            string text = "abcdefghijklmnopqrstuvwxyz";
            ValidateDotNetStringHashMatchesMarvin(text);
        }

        /// <summary>
        /// Verify that our Marvin checksum matches the .NET Marvin value for the same data.
        /// </summary>
        /// <param name="text">The text input for GetHashCode() and Marvin checksum computation.</param>
        private static void ValidateDotNetStringHashMatchesMarvin(string text)
        {
            if (GetMarvinType() == null)
            {
                return;
            }

            ulong defaultSeed = GetDotNetCurrentMarvinDefaultSeed();

            int expected = text.GetHashCode();

            byte[] input = Encoding.Unicode.GetBytes(text);
            int marvin = Marvin.ComputeHash32(input, defaultSeed);

            Assert.AreEqual(expected, marvin);
        }
#endif
    }
}
