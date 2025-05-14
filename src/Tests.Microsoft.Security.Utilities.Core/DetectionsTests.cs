// Copyright(c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;

using FluentAssertions;

using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Microsoft.Security.Utilities.Core
{
    [TestClass, ExcludeFromCodeCoverage]
    public class DetectionsTests
    {
        [TestMethod]
        public void Detections_Format()
        {
            var classifier = new SecretScanningSampleToken();
            var masker = new SecretMasker(new[] { classifier });
            string example = classifier.GenerateTruePositiveExamples().First();
            IEnumerable<Detection> detections = classifier.GetDetections(example, generateCrossCompanyCorrelatingIds: true);
            detections?.Count().Should().Be(1);
            Detection detection = detections.First();
            string truncated = Detections.TruncateSecret(example);
            string c3id = RegexPattern.GenerateCrossCompanyCorrelatingId(example);
            string expected = $"'{truncated}' is a non-functional secret scanning sample token. The correlating id for this detection is {c3id}.";
            Detections.Format(detection, example).Should().Be(expected);
        }

        [TestMethod]
        public void Detections_Truncate_ValidBase64()
        {
            using var rng = RandomNumberGenerator.Create();

            foreach (char specialChar in new char[] { '+', '/', '-', '_' })
            {
                for (int i = 33; i < 36; i++)
                {
                    byte[] bytes = new byte[i];
                    rng.GetBytes(bytes);
                    string base64 = Convert.ToBase64String(bytes);

                    // Ensure that every base64 special character is exercised.
                    base64 = specialChar + base64.Substring(1);

                    int paddingCount = base64.Count(c => c == '=');

                    int length = 8;
                    string truncated = Detections.TruncateSecret(base64, length);

                    // Because we truncate, + 1 for the ellipsis.
                    truncated.Length.Should().Be(length + paddingCount + 1);
                }
            }
        }

        [TestMethod]
        public void Detections_Truncate_InvalidBase64()
        {
            string[] invalidBase64Strings = [
                "XXXX1",
                "XXXX12",
                "XXXX123",
                "XXXX1===",
                "XXXX+-=", // Mix of special characters
                ];

            foreach (string invalidBase64 in invalidBase64Strings)
            {
                int length = 4;
                string truncated = Detections.TruncateSecret(invalidBase64, length);
                // Because we truncate, +1 for the ellipsis.
                truncated.Length.Should().Be(length + 1);
            }
        }

        [TestMethod]
        public void Detections_Truncate_WithinLengthThreshold()
        {
            string[] minimalValues = [
                null,
                "",
                "1",
                "12",
                "123",
                "1234",
                "=",
                "==",
                "===",
                "====",
                ];

            foreach (string minimalValue in minimalValues)
            {
                int length = 8;
                string truncated = Detections.TruncateSecret(minimalValue, length);
                truncated.Length.Should().Be(minimalValue?.Length ?? 0,
                    because: $"expected truncation '{truncated}' of input '{minimalValue}' to be of length {length}");
            }
        }
    }
}
