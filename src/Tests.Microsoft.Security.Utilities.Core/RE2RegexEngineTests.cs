// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using FluentAssertions;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using System.Linq;

namespace Microsoft.Security.Utilities.Core
{
    [TestClass]
    public class RE2RegexEngineTests
    {
        [TestMethod]
        public void RE2RegexEngine_RefineGroup()
        {
            // Scan data has a discrete component with 
            // a leading and trailing 'x' character.
            string scanData = $"x{nameof(scanData)}x";

            // The regex pattern defines a named group to extract
            // the scan data from between its encapsulating chars.
            string regex = $"x(?P<refine>{nameof(scanData)})x";

            var regexPattern = new RegexPattern(id: "1001", name: "MyRule", DetectionMetadata.None, regex);
            var masker = new SecretMasker([regexPattern], regexEngine: RE2RegexEngine.Instance);

            var detection = masker.DetectSecrets(scanData).FirstOrDefault();
            detection.Should().NotBe(default);

            string refined = scanData.Substring(detection.Start, detection.Length);
            refined.Should().Be(nameof(scanData));

            // Run the same test directly against the engine.
            var re2RegexEngine = new RE2RegexEngine();
            UniversalMatch flexMatch = re2RegexEngine.Matches(scanData, regex, captureGroup: "refine").FirstOrDefault();
            flexMatch.Should().NotBeNull();
            flexMatch.Value.Should().Be(nameof(scanData));
        }
    }
}
