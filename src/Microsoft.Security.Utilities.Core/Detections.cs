// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

global using static Microsoft.Security.Utilities.Detections;

using System;

namespace Microsoft.Security.Utilities
{
    public static class Detections
    {
        /// <summary>
        /// Given a detection originating in an input and a user-facing secret
        /// kind label, returns a message similar to: "'...79lNiA' is an Azure
        /// DevOps personal access token (PAT).'". A portion of the plaintext
        /// finding is preserved to introduce uniqueness in the output and to
        /// assist in searching the textual scan target in which the data was
        /// found.
        /// </summary>
        /// <param name="detection">A detection originating in a textual scan
        /// target.</param>
        /// <param name="input">The textual input that was scanned.</param>
        /// <returns>A message with a partial rendering of the plaintext
        /// finding, suitable for writing to the console, an IDE error list,
        /// etc.</returns>
        public static string Format(Detection detection, string input)
        {
            string match = input.Substring(detection.Start, detection.Length);
            string truncated = TruncateSecret(match);

            bool isHighConfidence = detection.Metadata.HasFlag(DetectionMetadata.HighConfidence);

            string verb = isHighConfidence ? "is" : "may comprise";

            string suffix = !string.IsNullOrEmpty(detection.CrossCompanyCorrelatingId)
                ? $" The correlating id for this detection is {detection.CrossCompanyCorrelatingId}."
                : string.Empty;

            return $"'{truncated}' {verb} {detection.Label}.{suffix}";
        }

        /// <summary>
        /// Truncates a string to a specified length, adding an ellipsis if any
        /// of the input string is removed. This helper will remove up to two
        /// trailing equals signs from the input string before truncating it.
        /// This is intended to help cover the standard case where a secret is
        /// base64-encoded data.
        /// </summary>
        /// <param name="text">The text to truncate.</param>
        /// <param name="lengthExclusiveOfEllipsis">The desired length of the
        /// truncated text, exclusive of the ellipsis, if added.</param>
        /// <returns>The rightmost truncated contents of the strength or the
        /// entire string (if its length is equal to or less than the specified
        /// length).</returns>
        public static string TruncateSecret(string text, int lengthExclusiveOfEllipsis = 6)
        {
            text ??= string.Empty;
            string truncatedText = text.Replace("-", "+").Replace("_", "/");

            try
            {
                // If we receive valid base64 or url-safe base64, we will
                // elide any trailing equal signs, so that the padding that's
                // retained in the truncated strength does not apply to the 
                // length constraint. 
                Convert.FromBase64String(truncatedText);
                truncatedText = text.TrimEnd('=');
            }
            catch (FormatException)
            {
            }

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
