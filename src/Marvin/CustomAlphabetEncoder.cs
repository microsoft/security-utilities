// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Microsoft.Security.Utilities
{
    /// <summary>
    /// Custom encoder class.
    /// </summary>
    public class CustomAlphabetEncoder
    {
        internal const string DefaultBase62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        [ThreadStatic]
        private static StringBuilder s_sb;

        private string alphabet;
        private uint baseEncoding;
        private Dictionary<char, uint> charToValueMap;

        /// <summary>
        /// Initializes a new instance of the <see cref="CustomAlphabetEncoder"/> class.
        /// </summary>
        /// <param name="customAlphabet">The alphabet to be used for all encoding/decoding operations.</param>
        public CustomAlphabetEncoder(string customAlphabet = DefaultBase62Alphabet)
        {
            alphabet = string.IsNullOrWhiteSpace(customAlphabet) ? DefaultBase62Alphabet : customAlphabet;
            baseEncoding = (uint)alphabet.Length;

            charToValueMap = new Dictionary<char, uint>();
            for (int i = 0; i < baseEncoding; i++)
            {
                // Repeated values in the custom alphabet will cause unreliable encoding/decoding.
                if(charToValueMap.ContainsKey(alphabet[i]))
                {
                    throw new ArgumentException(nameof(customAlphabet));
                }

                charToValueMap[alphabet[i]] = (uint)i;
            }
        }

        /// <summary>
        /// Encode an unsigned integer (a checksum) in a given character set.
        /// </summary>
        /// <param name="data">The unsigned integer to encode.</param>
        /// <returns>
        /// The unsigned integer encoded using the character set with which this class was instantiated.
        /// </returns>
        public string Encode(uint data)
        {
            s_sb ??= new StringBuilder();
            s_sb.Clear();

            while (data > 0)
            {
                s_sb.Append(alphabet[(int)(data % baseEncoding)]);
                data /= baseEncoding;
            }

            return new string(s_sb.ToString().Reverse().ToArray());
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
