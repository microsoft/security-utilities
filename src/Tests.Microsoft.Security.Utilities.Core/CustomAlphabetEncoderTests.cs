// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

using FluentAssertions;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities
{
    [TestClass, ExcludeFromCodeCoverage]
    public class CustomAlphabetEncoderTests
    {
        private const string PasswordCharacters = "abcdefghijklmnopqrstuvwxyz" +
                                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                                                  "1234567890" +
                                                  ".-_~";


        [TestMethod]
        public void CustomAlphabetEncoder_EncodeUintWithTestCases()
        {
            var random = new Random();

            var testCases = new[]
            {
                new
                {
                    Alphabet = String.Empty,
                    Input = uint.MaxValue,
                    ExpectedEncoded = "4gfFC3"
                },
                new
                {
                    Alphabet = String.Empty,
                    Input = (uint)2883656711,
                    ExpectedEncoded = "399Wq7"
                },
                new
                {
                    Alphabet = "abc",
                    Input = (uint)2883656711,
                    ExpectedEncoded = "cbbaccccaacccbbaabac"
                },
                new
                {
                    Alphabet = "abcdef",
                    Input = (uint)123456,
                    ExpectedEncoded = "cdfbdca"
                },
                new
                {
                    Alphabet = PasswordCharacters,
                    Input = (uint)956747778,
                    ExpectedEncoded = "aYB6eE"
                },
                new
                {
                    Alphabet = PasswordCharacters,
                    Input = (uint)1179413251,
                    ExpectedEncoded = "a.kybX"
                },
            };

            foreach (var testCase in testCases)
            {
                var testEncoder = new CustomAlphabetEncoder(testCase.Alphabet);
                string actualEncoded = testEncoder.Encode(testCase.Input);

                byte[] actualDecoded = testEncoder.Decode(actualEncoded);
                uint actualDecodedUint = BitConverter.ToUInt32(actualDecoded, 0);

                actualEncoded.Should().Be(testCase.ExpectedEncoded);
                actualDecodedUint.Should().Be(testCase.Input);
            }
        }

        [TestMethod]
        public void CustomAlphabetEncoder_ShouldEncodeAndDecodeValidAlphabets()
        {
            var random = new Random();

            var testInputs = new List<uint>
            {
                uint.MinValue,
                uint.MaxValue,
                (uint)random.Next(),
                (uint)random.Next(),
                (uint)random.Next()
            };

            foreach (string alphabet in GenerateValidAlphabetTestCases())
            {
                var testEncoder = new CustomAlphabetEncoder(alphabet);

                foreach (uint input in testInputs)
                {
                    string actualEncoded = testEncoder.Encode(input);

                    byte[] actualDecoded = testEncoder.Decode(actualEncoded);
                    uint actualDecodedUint = BitConverter.ToUInt32(actualDecoded, 0);

                    actualDecodedUint.Should().Be(input);
                }
            }
        }

        [TestMethod]
        public void CustomAlphabetEncoder_ShouldThrowInvalidArgumentExceptionIfAlphabetIsInvalid()
        {
            var testCases = new[]
            {
                new {
                    Alphabet = "a",
                    ExpectedMessage = "Alphabet must be at least 2 characters."
                },
                new {
                    Alphabet = "aaa",
                    ExpectedMessage = "Duplicate value detected in the alphabet."
                },
                new {
                    Alphabet = GenerateAsciiString(),
                    ExpectedMessage = "Forbidden character type detected in the alphabet"
                },
                new {
                    Alphabet = "abc\uD800",
                    ExpectedMessage = "Forbidden character type detected in the alphabet"
                },
                new {
                    Alphabet = "abc\uDC00",
                    ExpectedMessage = "Forbidden character type detected in the alphabet"
                },
                new {
                    Alphabet = GenerateAsciiString(130,132),
                    ExpectedMessage = "Forbidden character type detected in the alphabet"
                },
                new {
                    Alphabet = "₼abc",
                    ExpectedMessage = "Forbidden character type detected in the alphabet"
                },
                new {
                    Alphabet = "ﺀabc",
                    ExpectedMessage = "Forbidden character type detected in the alphabet"
                },
                new {
                    Alphabet = "∞abc",
                    ExpectedMessage = "Forbidden character type detected in the alphabet"
                },
                new {
                    Alphabet = "µabc",
                    ExpectedMessage = "Forbidden character type detected in the alphabet"
                },
            };

            foreach (var testCase in testCases)
            {
                Action action = () => new CustomAlphabetEncoder(testCase.Alphabet);

                action.Should().Throw<ArgumentException>().Where(e => e.Message.Contains(testCase.ExpectedMessage));
            }
        }

        [TestMethod]
        public void CustomAlphabetEncoder_ShouldThrowExceptionWithNullInputOnDecode()
        {
            var testEncoder = new CustomAlphabetEncoder("abc");
            string data = null;

            Action decodeAction = () => testEncoder.Decode(data);
            decodeAction.Should().Throw<ArgumentNullException>();
        }

        [TestMethod]
        public void CustomAlphabetEncoder_ShouldThrowExceptionIfDecodedCharNotInAlphabet()
        {
            string alphabet = "abc";
            string encodedInput = "123";
            var testEncoder = new CustomAlphabetEncoder(alphabet);

            Action decodeAction = () => testEncoder.Decode(encodedInput);
            decodeAction.Should().Throw<ArgumentException>();
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

        private IEnumerable<string> GenerateValidAlphabetTestCases()
        {
            var output = new List<string>
            {
                String.Empty,
            };

            // generate a sample of random test alphabets
            for (int i = 2; i < 94; i++)
            {
                output.Add(GenerateAsciiString(33, (33 + i)));
            }

            return output;
        }

        private string GenerateAsciiString(int low = 0, int high = 256)
        {
            var sb = new StringBuilder();

            for (int i = low; i < high; i++)
            {
                sb.Append((char)i);
            }

            return sb.ToString();
        }
    }
}
