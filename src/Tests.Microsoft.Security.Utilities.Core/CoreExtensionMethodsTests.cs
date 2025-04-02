// Copyright(c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;
using System.Linq;

using FluentAssertions;

using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Microsoft.Security.Utilities.Core
{
    [TestClass, ExcludeFromCodeCoverage]
    public class CoreExtensionMethodsTests
    {
        [TestMethod]
        public void CoreExtensionMethod_FormattedMessage()
        {
            var classifier = new SecretScanningSampleToken();
            var masker = new SecretMasker([classifier]);
            string example = classifier.GenerateTruePositiveExamples().First();
            var detections = classifier.GetDetections(example, generateCrossCompanyCorrelatingIds: true);
            detections?.Count().Should().Be(1);
            var detection = detections.First();
            string truncated = example.Truncate();
            string c3id = RegexPattern.GenerateCrossCompanyCorrelatingId(example);
            string expected = $"'{truncated}' is a non-functional secret scanning sample token. The correlating id for this detection is {c3id}.";
            detection.FormattedMessage(example).Should().Be(expected);
        }
    }
}
