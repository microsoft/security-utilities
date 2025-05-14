// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using FluentAssertions;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;


namespace Microsoft.Security.Utilities.Core
{
    [TestClass]
    public class AzureFunctionIdentifiableKeyTests
    {
        [TestMethod]
        public void AzureFunctionIdentifiableKey_GenerateTruePositiveExamples()
        {
            var classifier = new AzureFunctionIdentifiableKey();

            foreach (string example in classifier.GenerateTruePositiveExamples())
            {
                var masker = new SecretMasker([classifier]);
                Detection detection = masker.DetectSecrets(example).FirstOrDefault();
                detection.Should().NotBe(default);

                string refined = example.Substring(detection.Start, detection.Length);
                Tuple<string, string> result = classifier.GetMatchIdAndName(refined);
                result.Should().NotBeNull();
            }
        }
    }
}


