// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities
{
    using System;
    using FluentAssertions;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class CustomAlphabetEncoderTests
    {
        /// <summary>
        /// Test Encode Uint generates expected results given a provided or default alphabet.
        /// </summary>
        /// <param name="expected">The expected result of Encode for the given parameters.</param>
        /// <param name="input">The input to be encoded.</param>
        /// <param name="alphabet">The custom alphabet to use for encoding.</param>
        [TestMethod]
        [DataRow("399Wq7", 2883656711, null)]
        [DataRow("", null, null)]
        public void CustomAlphabetEncoder_EncodeUintWithDefaultAlphabet(string expected, uint input, string alphabet)
        {
            CustomAlphabetEncoder testEncoder = new CustomAlphabetEncoder(alphabet);
            string actualEncoded = testEncoder.Encode(input);
            Assert.AreEqual(expected, actualEncoded);

            byte[] actualDecoded = testEncoder.Decode(actualEncoded);
            uint actualDecodedUint = BitConverter.ToUInt32(actualDecoded, 0);

            Assert.AreEqual(input, actualDecodedUint);
        }

        /// <summary>
        /// Test encoding a byte array produces and then decoding the byte array produces the expected results.
        /// </summary>
        /// <param name="alphabet">The custom alphabet to use for encoding.</param>
        /// <param name="input">Input used to generate a byte array for encoding/decoding.</param>
        [TestMethod]
        [DataRow("ABC123", (uint)123456)]
        [DataRow("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_~", (uint)123456)]
        [DataRow("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_~", UInt32.MinValue)]
        [DataRow("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_~", UInt32.MaxValue)]
        public void CustomAlphabetEncoder_EncodeByteArrayWithCustomAlphabet(string alphabet, uint input)
        {
            CustomAlphabetEncoder testEncoder = new CustomAlphabetEncoder(alphabet);
            byte[] data = BitConverter.GetBytes(input);

            string actualEncoded = testEncoder.Encode(data);
            byte[] actualDecoded = testEncoder.Decode(actualEncoded);

            AssertByteArraysAreEqual(data, actualDecoded);
        }

        /// <summary>
        /// Test that correct exception is thrown if byte array is out of the allowed uint range.
        /// </summary>
        /// <param name="alphabet">The alphabet with which to instantiate the CustomAlphabetEncoder.</param>
        /// <param name="testInput">Example input which should throw an exception.</param>
        [TestMethod]
        [DataRow("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_~", (long)UInt32.MinValue - 1)]
        [DataRow("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_~", (long)UInt32.MaxValue + 1)]
        public void CustomAlphabetEncoder_ShouldValidateUintOnEncodeByteArray(string alphabet, long testInput)
        {
            CustomAlphabetEncoder testEncoder = new CustomAlphabetEncoder(alphabet);
            byte[] data = BitConverter.GetBytes(testInput);

            Action action = () => testEncoder.Encode(data);
            action.Should().Throw<ArgumentOutOfRangeException>();
        }

        /// <summary>
        /// Test that the correct exception is thrown if byte array input is null on encode.
        /// </summary>
        [TestMethod]
        public void CustomAlphabetEncoder_ShouldThrowExceptionWithNullInputOnEncodeByteArray()
        {
            CustomAlphabetEncoder testEncoder = new CustomAlphabetEncoder("abc");
            byte[] data = null;

            Action encodeAction = () => testEncoder.Encode(data);
            encodeAction.Should().Throw<ArgumentNullException>();
        }

        /// <summary>
        /// Test that the correct exception is thrown if string input is null on decode.
        /// </summary>
        [TestMethod]
        public void CustomAlphabetEncoder_ShouldThrowExceptionWithNullInputOnDecodeByteArray()
        {
            CustomAlphabetEncoder testEncoder = new CustomAlphabetEncoder("abc");
            string data = null;

            Action decodeAction = () => testEncoder.Decode(data);
            decodeAction.Should().Throw<ArgumentNullException>();
        }

        /// <summary>
        /// Compare values of a byte array instead of references of a byte array.
        /// </summary>
        /// <param name="expected">The expected byte array content.</param>
        /// <param name="actual">The byte array content being tested.</param>
        private void AssertByteArraysAreEqual(byte[] expected, byte[] actual)
        {
            actual.Should().BeEquivalentTo(expected);
            
            for(int i = 0; i < expected.Length; i++)
            {
                actual[i].Should().Be(expected[i]);
            }
        }
    }
}
