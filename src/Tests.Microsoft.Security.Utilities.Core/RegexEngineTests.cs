// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using FluentAssertions;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;

namespace Microsoft.Security.Utilities.Core
{
    [TestClass]
    public class RegexEngineTests
    {
        [TestMethod]
        public void RegexEngine_RE2_RefineGroup()
        {
            RegexEngine_RefineGroup(RE2RegexEngine.Instance);
        }

        [TestMethod]
        public void RegexEngine_CachedDotNet_RefineGroup()
        {
            RegexEngine_RefineGroup(RE2RegexEngine.Instance);
        }

        private static void RegexEngine_RefineGroup(IRegexEngine engine)
        {
            // Scan data has a discrete component with 
            // a leading and trailing 'x' character.
            string scanData = $"x{nameof(scanData)}x";

            // The regex pattern defines a named group to extract
            // the scan data from between its encapsulating chars.
            string regex = $"x(?P<refine>{nameof(scanData)})x";

            var regexPattern = new RegexPattern(id: "1001",
                                                name: "MyRule",
                                                label: "a test secret",
                                                DetectionMetadata.None,
                                                regex);
            var masker = new SecretMasker([regexPattern], regexEngine: RE2RegexEngine.Instance);

            Detection detection = masker.DetectSecrets(scanData).FirstOrDefault();
            detection.Should().NotBe(default);

            string refined = scanData.Substring(detection.Start, detection.Length);
            refined.Should().Be(nameof(scanData));

            // Run the same test directly against the engine.
            UniversalMatch match = engine.Matches(scanData, regex, captureGroup: "refine").FirstOrDefault();
            match.Should().NotBeNull();
            match.Success.Should().BeTrue();
            match.Index.Should().Be(1); // 'x' at the start
            match.Length.Should().Be(nameof(scanData).Length);
            match.Value.Should().Be(nameof(scanData));
        }


        [TestMethod]
        public void RegexEngine_RE2_NoCaptureGroup()
        {
            RegexEngine_NoCaptureGroup(RE2RegexEngine.Instance);
        }

        [TestMethod]
        public void RegexEngine_CachedDotNet_NoCaptureGroup()
        {
            RegexEngine_NoCaptureGroup(RE2RegexEngine.Instance);
        }

        private static void RegexEngine_NoCaptureGroup(IRegexEngine engine)
        {
            string scanData = $"x{nameof(scanData)}x";
            string regex = $"x(?P<refine>{nameof(scanData)})x";

            UniversalMatch match = engine.Matches(scanData, regex).FirstOrDefault();
            match.Should().NotBeNull();
            match.Success.Should().BeTrue();
            match.Index.Should().Be(0);
            match.Length.Should().Be(scanData.Length);
            match.Value.Should().Be(scanData);
        }

#if NET
        [TestMethod]
        public void RegexEngine_CachedDotNet_NoCaptureGroupUsingSpan()
        {
            ReadOnlySpan<char> scanData;
            string fullString = $"yx{nameof(scanData)}xy";
            scanData = fullString.AsSpan()[1..^1]; // Exclude leading and trailing 'y'
            string regex = $"x(?P<refine>{nameof(scanData)})x";

            UniversalMatch match = CachedDotNetRegex.Instance.Matches(scanData, regex).FirstOrDefault();
            match.Should().NotBeNull();
            match.Success.Should().BeTrue();
            match.Index.Should().Be(0);
            match.Length.Should().Be(scanData.Length);
            match.Value.Should().Be(scanData.ToString());
        }
#endif
    }
}
