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
        [TestMethod]
        [DataRow("399Wq7", 2883656711, null)]
        [DataRow("", null, null)]
        public void CustomAlphabetEncoder_EncodeUintWithDefaultAlphabet(string expected, uint input, string alphabet)
        {
            var testEncoder = new CustomAlphabetEncoder(alphabet);
            string actualEncoded = testEncoder.Encode(input);
            Assert.AreEqual(expected, actualEncoded);

            byte[] actualDecoded = testEncoder.Decode(actualEncoded);
            uint actualDecodedUint = BitConverter.ToUInt32(actualDecoded, 0);

            Assert.AreEqual(input, actualDecodedUint);
        }

        [TestMethod]
        [DataRow("ABC123", (uint)123456)]
        [DataRow("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_~", (uint)123456)]
        [DataRow("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_~", UInt32.MinValue)]
        [DataRow("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_~", UInt32.MaxValue)]
        public void CustomAlphabetEncoder_EncodeByteArrayWithCustomAlphabet(string alphabet, uint input)
        {
            var testEncoder = new CustomAlphabetEncoder(alphabet);
            byte[] expectedDecoded = BitConverter.GetBytes(input);

            string actualEncoded = testEncoder.Encode(input);
            byte[] actualDecoded = testEncoder.Decode(actualEncoded);

            actualDecoded.Should().BeEquivalentTo(expectedDecoded);
        }

        [TestMethod]
        [DataRow("abc", "abc")]
        [DataRow("abc", "abcdef")]
        [DataRow(".!@#$%&*", "abcdef")]
        public void CustomAlphabetEncoder_EncodeByteArrayFromStringWithCustomAlphabet(string alphabet, string input)
        {
            var testEncoder = new CustomAlphabetEncoder(alphabet);
            int data = input.GetHashCode();
            byte[] expected = BitConverter.GetBytes(data);

            string actualEncoded = testEncoder.Encode((uint)data);
            byte[] actualDecoded = testEncoder.Decode(actualEncoded);

            actualDecoded.Should().BeEquivalentTo(expected);
        }

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

        [TestMethod]
        public void CustomAlphabetEncoder_ShouldThrowExceptionWithNullInputOnDecodeByteArray()
        {
            var testEncoder = new CustomAlphabetEncoder("abc");
            string data = null;

            Action decodeAction = () => testEncoder.Decode(data);
            decodeAction.Should().Throw<ArgumentNullException>();
        }

        [TestMethod]
        public void CustomAlphabetEncoder_VerifyStaticAndInstanceDate()
        {
            var testEncoder1 = new CustomAlphabetEncoder("abcdef");
            uint randomChecksum = uint.MaxValue - 1000;

            string encodedChecksum1 = testEncoder1.Encode(randomChecksum);

            var testEncoder2 = new CustomAlphabetEncoder("abdefghijklmnopqrstuv");

            string encodedChecksum2 = testEncoder1.Encode(randomChecksum);

            encodedChecksum1.Should().Be(encodedChecksum2);
        }
    }
}
