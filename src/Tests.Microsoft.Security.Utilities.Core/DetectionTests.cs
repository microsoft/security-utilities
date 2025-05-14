// Copyright(c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.Diagnostics.CodeAnalysis;
using System.Reflection.Emit;

namespace Tests.Microsoft.Security.Utilities
{
    [TestClass, ExcludeFromCodeCoverage]
    public class DetectionTests
    {
        [TestMethod]
        public void Detection_ConstructorValuesSet()
        {
            string id = $"{Guid.NewGuid()}";
            string name = $"{Guid.NewGuid()}";
            string label = $"{Guid.NewGuid()}";
            string crossCompanyCorrelatingId = $"{Guid.NewGuid()}";
            string redactionToken = $"{Guid.NewGuid()}";

            var metadata = (DetectionMetadata)0B_11111;
            int start = Math.Max(1, (int)DateTime.UtcNow.Ticks % 99);
            int length = Math.Max(1, (int)DateTime.UtcNow.Ticks % 99);
            var rotationPeriod = TimeSpan.FromSeconds(Math.Max(1, DateTime.UtcNow.Second));

            var detection = new Detection(id,
                                          name,
                                          label,
                                          start,
                                          length,
                                          metadata,
                                          rotationPeriod,
                                          crossCompanyCorrelatingId,
                                          redactionToken);

            Assert.AreEqual(id, detection.Id);
            Assert.AreEqual(name, detection.Name);
            Assert.AreEqual(label, detection.Label);
            Assert.AreEqual(start, detection.Start);
            Assert.AreEqual(length, detection.Length);
            Assert.AreEqual(metadata, detection.Metadata);
            Assert.AreEqual(start + length, detection.End);
            Assert.AreEqual(rotationPeriod, detection.RotationPeriod);
            Assert.AreEqual(redactionToken, detection.RedactionToken);
            Assert.AreEqual(crossCompanyCorrelatingId, detection.CrossCompanyCorrelatingId);

            detection = new Detection(string.Empty,
                                      string.Empty,
                                      string.Empty,
                                      int.MinValue,
                                      int.MaxValue,
                                      0,
                                      rotationPeriod: default,
                                      string.Empty);

            Assert.AreNotEqual(id, detection.Id);
            Assert.AreNotEqual(name, detection.Name);
            Assert.AreNotEqual(label, detection.Label);
            Assert.AreNotEqual(start, detection.Start);
            Assert.AreNotEqual(length, detection.Length);
            Assert.AreNotEqual(metadata, detection.Metadata);
            Assert.AreNotEqual(start + length, detection.End);
            Assert.AreNotEqual(rotationPeriod, detection.CrossCompanyCorrelatingId);
            Assert.AreNotEqual(rotationPeriod, detection.RotationPeriod);
            Assert.AreNotEqual(redactionToken, detection.RedactionToken);
        }
    }
}