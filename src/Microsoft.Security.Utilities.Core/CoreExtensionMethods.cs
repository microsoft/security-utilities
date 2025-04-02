// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal static class CoreExtensionMethods
    {
        public static ISet<string> ToSet(this string value)
        {
            return new HashSet<string> { value };
        }
        public static ISet<string> ToSet(this IEnumerable<string> value)
        {
            return new HashSet<string>(value);
        }

        /// <summary>
        /// Given a detection originating in an input and a user-facing secret
        /// kind label, returns a message similar to: "'...79lNiA' is an Azure
        /// DevOps personal access token (PAT).'". A portion of the plaintext
        /// finding is preserved to introduce uniqueness in the output and to
        /// assist in searching the textual scan target in which the data was
        /// found.
        /// </summary>
        /// <param name="value">A detection originating in a textual scan
        /// target.</param>
        /// <param name="input">The textual input that was scanned.</param>
        /// <returns>A message with a partial rendering of the plaintext
        /// finding, suitable for writing to the console, an IDE error list,
        /// etc.</returns>
        public static string FormattedMessage(this Detection value, string input)
        {
            string truncated = input.Substring(value.Start, value.Length).Truncate();

            bool isHighConfidence = value.Metadata.HasFlag(DetectionMetadata.HighConfidence);

            string verb = isHighConfidence ? "is" : "may comprise";

            string suffix = !string.IsNullOrEmpty(value.CrossCompanyCorrelatingId)
                ? $" The correlating id for this detection is {value.CrossCompanyCorrelatingId}."
                : string.Empty;
            
            return $"'{truncated}' {verb} {value.Label}.{suffix}";
        }

        /// <summary>
        /// Truncates a string to a specified length, adding an ellipsis if any
        /// of the input string is removed.
        /// </summary>
        /// <param name="text">The text to truncate.</param>
        /// <param name="lengthExclusiveOfEllipsis">The desired length of the truncated text, exclusive of the ellipsis, if added.</param>
        /// <returns>The rightmost truncated contents of the strength or the entire string (if its length is equal to or less than the specified length).</returns>
        public static string Truncate(this string text, int lengthExclusiveOfEllipsis = 6)
        {
            text ??= string.Empty;
            string truncatedText = text.TrimEnd('=');
            string suffix = new string('=', text.Length - truncatedText.Length);

            if (truncatedText.Length <= lengthExclusiveOfEllipsis)
            {
                return text;
            }

            truncatedText = truncatedText.Substring(truncatedText.Length - lengthExclusiveOfEllipsis);

            bool charsElided = truncatedText.Length != text.Length;

            // "\u2026" == "…"
            return (charsElided ? "\u2026" : string.Empty) +
                   truncatedText.Substring(truncatedText.Length - lengthExclusiveOfEllipsis) +
                   (charsElided ? suffix : string.Empty);
        }
    }
}
