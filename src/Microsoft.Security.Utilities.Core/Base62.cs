// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace Base62
{
    // This source code brought to us compliments of the Base62.Net project. Thanks!
    // https://github.com/JoyMoe/Base62.Net/blob/dev/LICENSE
    public static class EncodingExtensions
    {
        [ThreadStatic]
        private static StringBuilder s_sb;

        private const string DefaultCharacterSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        private const string InvertedCharacterSet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        /// <summary>
        /// Encode a 2-byte number with Base62
        /// </summary>
        /// <param name="original">String</param>
        /// <param name="inverted">Use inverted character set</param>
        /// <returns>Base62 string</returns>
        public static string ToBase62(this short original, bool inverted = false)
        {
            var array = BitConverter.GetBytes(original);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(array);
            }

            return array.ToBase62(inverted);
        }

        /// <summary>
        /// Encode a 4-byte number with Base62
        /// </summary>
        /// <param name="original">String</param>
        /// <param name="inverted">Use inverted character set</param>
        /// <returns>Base62 string</returns>
        public static string ToBase62(this int original, bool inverted = false)
        {
            var array = BitConverter.GetBytes(original);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(array);
            }

            return array.ToBase62(inverted);
        }

        /// <summary>
        /// Encode a 8-byte number with Base62
        /// </summary>
        /// <param name="original">String</param>
        /// <param name="inverted">Use inverted character set</param>
        /// <returns>Base62 string</returns>
        public static string ToBase62(this long original, bool inverted = false)
        {
            var array = BitConverter.GetBytes(original);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(array);
            }

            return array.ToBase62(inverted);
        }

        /// <summary>
        /// Encode a string with Base62
        /// </summary>
        /// <param name="original">String</param>
        /// <param name="inverted">Use inverted character set</param>
        /// <returns>Base62 string</returns>
        public static string ToBase62(this string original, bool inverted = false)
        {
            return Encoding.UTF8.GetBytes(original).ToBase62(inverted);
        }

        /// <summary>
        /// Encode a byte array with Base62
        /// </summary>
        /// <param name="original">Byte array</param>
        /// <param name="inverted">Use inverted character set</param>
        /// <returns>Base62 string</returns>
        public static string ToBase62(this byte[] original, bool inverted = false)
        {
            var characterSet = inverted ? InvertedCharacterSet : DefaultCharacterSet;
            var arr = Array.ConvertAll(original, t => (int)t);

            var converted = BaseConvert(arr, 256, 62);
            s_sb ??= new StringBuilder();
            s_sb.Clear();
            foreach (var t in converted)
            {
                s_sb.Append(characterSet[t]);
            }
            return s_sb.ToString();
        }

        /// <summary>
        /// Decode a base62-encoded string
        /// </summary>
        /// <param name="base62">Base62 string</param>
        /// <param name="inverted">Use inverted character set</param>
        /// <returns>Byte array</returns>
        public static T FromBase62<T>(this string base62, bool inverted = false)
        {
            var array = base62.FromBase62(inverted);

            switch (Type.GetTypeCode(typeof(T)))
            {
                case TypeCode.String:
                    return (T)Convert.ChangeType(Encoding.UTF8.GetString(array), typeof(T), CultureInfo.InvariantCulture);
                case TypeCode.Int16:
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(array);
                    }

                    return (T)Convert.ChangeType(BitConverter.ToInt16(array, 0), typeof(T), CultureInfo.InvariantCulture);
                case TypeCode.Int32:
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(array);
                    }

                    return (T)Convert.ChangeType(BitConverter.ToInt32(array, 0), typeof(T), CultureInfo.InvariantCulture);
                case TypeCode.Int64:
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(array);
                    }

                    return (T)Convert.ChangeType(BitConverter.ToInt64(array, 0), typeof(T), CultureInfo.InvariantCulture);
                default:
                    throw new Exception($"Type of {typeof(T)} does not support.");
            }
        }

        /// <summary>
        /// Decode a base62-encoded string
        /// </summary>
        /// <param name="base62">Base62 string</param>
        /// <param name="inverted">Use inverted character set</param>
        /// <returns>Byte array</returns>
        public static byte[] FromBase62(this string base62, bool inverted = false)
        {
            if (string.IsNullOrWhiteSpace(base62))
            {
                throw new ArgumentNullException(nameof(base62));
            }

            var characterSet = inverted ? InvertedCharacterSet : DefaultCharacterSet;
            var arr = Array.ConvertAll(base62.ToCharArray(), characterSet.IndexOf);

            var converted = BaseConvert(arr, 62, 256);
            return Array.ConvertAll(converted, Convert.ToByte);
        }

        private static int[] BaseConvert(int[] source, int sourceBase, int targetBase)
        {
            var result = new List<int>();
            var leadingZeroCount = Math.Min(source.TakeWhile(x => x == 0).Count(), source.Length - 1);
            int count;
            while ((count = source.Length) > 0)
            {
                var quotient = new List<int>();
                var remainder = 0;
                for (var i = 0; i != count; i++)
                {
                    var accumulator = source[i] + remainder * sourceBase;
                    var digit = accumulator / targetBase;
                    remainder = accumulator % targetBase;
                    if (quotient.Count > 0 || digit > 0)
                    {
                        quotient.Add(digit);
                    }
                }

                result.Insert(0, remainder);
                source = quotient.ToArray();
            }
            result.InsertRange(0, Enumerable.Repeat(0, leadingZeroCount));
            return result.ToArray();
        }
    }
}