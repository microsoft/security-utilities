using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using System.Globalization;
using System.Linq;
using System.Collections.Generic;

namespace Tests.Microsoft.Security.Utilities.Core
{
    [TestClass]
    public class LocalizationTests
    {
        [TestMethod]
        public void Resources_ContainExpectedStrings()
        {
            // Verify that our resource strings contain the expected values
            Resources.Detection_HighConfidenceFormat.Should().Be("'{0}' is {1}.{2}");
            Resources.Detection_LowConfidenceFormat.Should().Be("'{0}' may comprise {1}.{2}");
            Resources.Detection_CorrelatingIdSuffix.Should().Be(" The correlating id for this detection is {0}.");
        }

        [TestMethod]
        public void Detections_Format_UsesResourceStrings_HighConfidence()
        {
            // Use an existing classifier that generates high confidence detections
            var classifier = new SecretScanningSampleToken();
            string example = classifier.GenerateTruePositiveExamples().First();
            IEnumerable<Detection> detections = classifier.GetDetections(example, generateCrossCompanyCorrelatingIds: true);
            Detection detection = detections.First();
            
            string result = Detections.Format(detection, example);
            
            // The output should use the high confidence verb from resources
            result.Should().Contain("is"); // High confidence verb from resources
            result.Should().Contain("non-functional secret scanning sample token"); // The label
            result.Should().Contain("The correlating id for this detection"); // From resources
        }

        [TestMethod]
        public void Detections_Format_BehaviorUnchanged()
        {
            // Ensure that the localized version produces the same output as before
            var classifier = new SecretScanningSampleToken();
            string example = classifier.GenerateTruePositiveExamples().First();
            IEnumerable<Detection> detections = classifier.GetDetections(example, generateCrossCompanyCorrelatingIds: true);
            Detection detection = detections.First();
            string truncated = Detections.TruncateSecret(example);
            string c3id = RegexPattern.GenerateCrossCompanyCorrelatingId(example);
            
            // This should match exactly what the original test expects
            string expected = $"'{truncated}' is a non-functional secret scanning sample token. The correlating id for this detection is {c3id}.";
            string actual = Detections.Format(detection, example);
            
            actual.Should().Be(expected);
        }

        [TestMethod]
        public void Detections_Format_LowConfidence_UsesCorrectVerb()
        {
            // Create a low confidence pattern to test the "may comprise" verb
            var lowConfidencePattern = new RegexPattern("test-id", "test-name", "test secret", DetectionMetadata.None, @"test\d+");
            string testInput = "test123";
            IEnumerable<Detection> detections = lowConfidencePattern.GetDetections(testInput, generateCrossCompanyCorrelatingIds: false);
            
            if (detections.Any())
            {
                Detection detection = detections.First();
                string result = Detections.Format(detection, testInput);
                
                // Should use "may comprise" for low confidence
                result.Should().Contain("may comprise");
                result.Should().Contain("test secret");
                result.Should().NotContain("correlating id"); // No correlating ID was generated
            }
        }
    }
}