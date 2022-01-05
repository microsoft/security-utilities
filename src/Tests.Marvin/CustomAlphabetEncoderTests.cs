// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities
{

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

            actualDecoded.Should().BeEquivalentTo(data);
        }

        /// <summary>
        /// Test encoding a byte array produces and then decoding the byte array produces the expected results.
        /// </summary>
        /// <param name="alphabet">The custom alphabet to use for encoding.</param>
        /// <param name="input">Input used to generate a byte array for encoding/decoding.</param>
        [TestMethod]
        [DataRow("abc", "abc")]
        [DataRow("abc", "abcdef")]
        [DataRow(".!@#$%&*", "abcdef")]
        public void CustomAlphabetEncoder_EncodeByteArrayFromStringWithCustomAlphabet(string alphabet, string input)
        {
            CustomAlphabetEncoder testEncoder = new CustomAlphabetEncoder(alphabet);
            int data = input.GetHashCode();
            byte[] expected = BitConverter.GetBytes(data);

            string actualEncoded = testEncoder.Encode((uint)data);
            byte[] actualDecoded = testEncoder.Decode(actualEncoded);

            actualDecoded.Should().BeEquivalentTo(expected);
        }

        /// <summary>
        /// Test to ensure encode and decode are not impacted by duplicate characters in a custom alphabet.
        /// </summary>
        /// <param name="alphabet">Custom alphabet test case with duplicate characters.</param>
        [TestMethod]
        [DataRow("abcabc")]
        [DataRow("abbc")]
        [DataRow("11 2 3")]
        [DataRow("1 2 3 a b c")]
        public void CustomAlphabetEncoder_ShouldThrowInvalidArgumentExceptionIfCharacterRepeats(string alphabet)
        {
            Action action = () => new CustomAlphabetEncoder(alphabet);

            action.Should().Throw<ArgumentException>();
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
    }
}
