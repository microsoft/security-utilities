// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Custom encoder class.
    /// </summary>
    public class CustomAlphabetEncoder
    {
        internal const string DefaultBase62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        [ThreadStatic]
        private static StringBuilder sb;
        private static string alphabet;
        private static uint baseEncoding;
        private static Dictionary<char, uint> charToValueMap;

        /// <summary>
        /// Initializes a new instance of the <see cref="CustomAlphabetEncoder"/> class.
        /// </summary>
        /// <param name="customAlphabet">The alphabet to be used for all encoding/decoding operations.</param>
        public CustomAlphabetEncoder(string customAlphabet = DefaultBase62Alphabet)
        {
            alphabet = string.IsNullOrWhiteSpace(customAlphabet) ? DefaultBase62Alphabet : customAlphabet;
            baseEncoding = (uint)alphabet.Length;

            charToValueMap = new Dictionary<char,uint>();
            for (int i = 0; i < alphabet.Length; i++)
            {
                charToValueMap[alphabet[i]] = (uint)i;
            }
        }

        /// <summary>
        /// Encode a byte array in a given character set.
        /// </summary>
        /// <param name="data">The byte array to encode. Must be 4 bytes or less.</param>
        /// <returns>
        /// The byte array encoded using the character set with which this class was instantiated.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown if 'data' is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if the length of the data array is greater than 4.</exception>
        public string Encode(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            // input 'data' is restricted to the range uint.MinValue to uint.MaxValue
            if (data.Length < 0 || data.Length > 4)
            {
                throw new ArgumentOutOfRangeException(nameof(data));
            }

            if (data.Length == 0)
            {
                return string.Empty;
            }

            uint convertedInput = BitConverter.ToUInt32(data, 0);

            return Encode(convertedInput);
        }

        /// <summary>
        /// Encode an unsigned integer (a checksum) in a given character set.
        /// </summary>
        /// <param name="data">The unsigned integer to encode.</param>
        /// <returns>
        /// The unsigned integer encoded using the character set with which this class was instantiated.
        /// </returns>
        public string Encode (uint data)
        {
            sb ??= new StringBuilder();
            sb.Clear();

            while (data > 0)
            {
                sb.Append(alphabet[(int)(data % baseEncoding)]);
                data /= baseEncoding;
            }

            return new string(sb.ToString().Reverse().ToArray());
        }

        /// <summary>
        /// Decode a byte array from a given character set.
        /// </summary>
        /// <param name="encodedValue">The encoded byte array to decode.</param>
        /// <returns>
        /// The byte array encoded using the character set wit which this class was instantiated.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="encodedValue"/> is null.</exception>
        public byte[] Decode(string encodedValue)
        {
            if (encodedValue == null)
            {
                throw new ArgumentNullException(nameof(encodedValue));
            }

            uint decodedValue = 0;

            foreach (char c in encodedValue)
            {
                decodedValue *= baseEncoding;
                decodedValue += charToValueMap[c];
            }

            return BitConverter.GetBytes(decodedValue);
        }
    }
}
