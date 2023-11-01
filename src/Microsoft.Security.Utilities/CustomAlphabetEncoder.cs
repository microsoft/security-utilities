// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Schema;

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
        private Dictionary<char, uint> charToValueMap;

        /// <summary>
        /// Initializes a new instance of the <see cref="CustomAlphabetEncoder"/> class.
        /// </summary>
        /// <param name="customAlphabet">The alphabet to be used for all encoding/decoding operations. Must consist of nonwhitespace ASCII letters, numbers, and/or punctuation.</param>
        /// <exception cref="ArgumentException">customAlphabet contains a duplicate or forbidden character.</exception>
        public CustomAlphabetEncoder(string customAlphabet = DefaultBase62Alphabet)
        {
            alphabet = string.IsNullOrWhiteSpace(customAlphabet) ? DefaultBase62Alphabet : customAlphabet;

            if (alphabet.Length < 2)
            {
                throw new ArgumentException(nameof(customAlphabet), "Alphabet must be at least 2 characters.");
            }

            charToValueMap = new Dictionary<char, uint>();
            for (int i = 0; i < alphabet.Length; i++)
            {
                // Repeated values in the custom alphabet will cause unreliable encoding/decoding.
                if (charToValueMap.ContainsKey(alphabet[i]))
                {
                    throw new ArgumentException(nameof(customAlphabet), "Duplicate value detected in the alphabet.");
                }

                if (Char.IsWhiteSpace(alphabet[i]) || Char.IsSurrogate(alphabet[i]) || (int)alphabet[i] > 127)
                {
                    throw new ArgumentException(nameof(customAlphabet), $"Forbidden character type detected in the alphabet: {alphabet[i]}.");
                }

                charToValueMap[alphabet[i]] = (uint)i;
            }
        }

        /// <summary>
        /// Encode an unsigned integer (a checksum) in a given character set.
        /// </summary>
        /// <param name="data">The unsigned integer to encode.</param>
        /// <param name="minLength">
        /// The minimum length for encoded result. Defaults to 6 to match common checksum implementation cases.
        /// </param>
        /// <returns>
        /// The unsigned integer encoded using the character set with which this class was instantiated.
        /// </returns>
        public string Encode(uint data, int minLength = 6)
        {
            s_sb ??= new StringBuilder();
            s_sb.Clear();

            while (data > 0)
            {
                s_sb.Append(alphabet[(int)(data % (uint)alphabet.Length)]);
                data /= (uint)alphabet.Length;
            }

            while (s_sb.Length < minLength)
            {
                s_sb.Append(alphabet[0]);
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
            uint alphabetLength = (uint)alphabet.Length;

            foreach (char c in encodedValue)
            {
                if (!charToValueMap.ContainsKey(c))
                {
                    throw new ArgumentException(nameof(encodedValue), "Alphabet does not contain all characters in input");
                }

                decodedValue *= alphabetLength;
                decodedValue += charToValueMap[c];
            }

            return BitConverter.GetBytes(decodedValue);
        }
        
        /// <summary>
        /// Sets a custom alphabet to be used for all encoding and decoding operations.
        /// </summary>
        /// <param name="customAlphabet">A string representing the custom alphabet. It must consist of non-whitespace ASCII characters, including letters, numbers, and/or punctuation.</param>
        /// <exception cref="ArgumentException">Throws an exception if the alphabet contains duplicates or contains forbidden characters.</exception>
        /// <remarks>
        /// This method allows dynamic changes to the alphabet used for encoding and decoding data. Before setting a new alphabet, the method performs checks for duplicates and the presence of forbidden characters.
        /// </remarks>
        public void SetCustomAlphabet(string customAlphabet)
        {
            if (customAlphabet == null)
            {
                throw new ArgumentNullException(nameof(customAlphabet));
            }

            Dictionary<char, uint> newCharToValueMap = new Dictionary<char, uint>();

            for (int i = 0; i < customAlphabet.Length; i++)
            {
                if (newCharToValueMap.ContainsKey(customAlphabet[i]))
                {
                    throw new ArgumentException(nameof(customAlphabet), "Duplicate value detected in the new alphabet.");
                }

                if (Char.IsWhiteSpace(customAlphabet[i]) || Char.IsSurrogate(customAlphabet[i]) || (int)customAlphabet[i] > 127)
                {
                    throw new ArgumentException(nameof(customAlphabet), $"Forbidden character type detected in the new alphabet: {customAlphabet[i]}.");
                }

                newCharToValueMap[customAlphabet[i]] = (uint)i;
            }

            alphabet = customAlphabet;
            charToValueMap = newCharToValueMap;
        }
    }
}
