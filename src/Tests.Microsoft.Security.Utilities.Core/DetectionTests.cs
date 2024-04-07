// Copyright(c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.Diagnostics.CodeAnalysis;

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
            string sha256Hash = $"{Guid.NewGuid()}";
            string redactionToken = $"{Guid.NewGuid()}";

            var metadata = (DetectionMetadata)0B_11111;
            int start = Math.Min(1, (int)DateTime.UtcNow.Ticks % 99);
            int length = Math.Min(1, (int)DateTime.UtcNow.Ticks % 99);
            TimeSpan rotationPeriod = TimeSpan.FromSeconds(Math.Min(1, DateTime.UtcNow.Second));

            var detection = new Detection(id,
                                          name,
                                          start,
                                          length,
                                          metadata,
                                          rotationPeriod,
                                          sha256Hash);

            Assert.AreEqual(id, detection.Id);
            Assert.AreEqual(name, detection.Name);
            Assert.AreEqual(start, detection.Start);
            Assert.AreEqual(length, detection.Length);
            Assert.AreEqual(metadata, detection.Metadata);
            Assert.AreEqual(start + length, detection.End);
            Assert.AreEqual(rotationPeriod, detection.RotationPeriod);
            Assert.AreEqual(sha256Hash, detection.RedactionToken);

            detection = new Detection(string.Empty,
                                      string.Empty,
                                      int.MinValue,
                                      int.MaxValue,
                                      0,
                                      rotationPeriod: default,
                                      string.Empty);

            Assert.AreNotEqual(id, detection.Id);
            Assert.AreNotEqual(name, detection.Name);
            Assert.AreNotEqual(start, detection.Start);
            Assert.AreNotEqual(length, detection.Length);
            Assert.AreNotEqual(metadata, detection.Metadata);
            Assert.AreNotEqual(start + length, detection.End);
            Assert.AreNotEqual(rotationPeriod, detection.RotationPeriod);
            Assert.AreNotEqual(sha256Hash, detection.RedactionToken);
        }

        [TestMethod]
        public void Detection_PropertyValuesSet()
        {
            string id = $"{Guid.NewGuid()}";
            string name = $"{Guid.NewGuid()}";
            string sha256Hash = $"{Guid.NewGuid()}";
            string redactionToken = $"{Guid.NewGuid()}";

            var metadata = (DetectionMetadata)0B_11111;
            int start = (int)DateTime.UtcNow.Ticks % 99;
            int length = (int)DateTime.UtcNow.Ticks % 99;
            TimeSpan rotationPeriod = TimeSpan.FromSeconds(DateTime.UtcNow.Second);

            var detection = new Detection
            {
                Id = id,
                Name = name,
                Start = start,
                Length = length,
                Metadata = metadata,
                RotationPeriod = rotationPeriod,
                RedactionToken = sha256Hash,
            };

            Assert.AreEqual(id, detection.Id);
            Assert.AreEqual(name, detection.Name);
            Assert.AreEqual(start, detection.Start);
            Assert.AreEqual(length, detection.Length);
            Assert.AreEqual(metadata, detection.Metadata);
            Assert.AreEqual(start + length, detection.End);
            Assert.AreEqual(rotationPeriod, detection.RotationPeriod);
            Assert.AreEqual(sha256Hash, detection.RedactionToken);

            detection = new Detection
            {
                Id = string.Empty,
                Name = string.Empty,
                Start = int.MinValue,
                Length = int.MaxValue,
                Metadata = 0,
                RotationPeriod = default,
                RedactionToken = string.Empty
            };

            Assert.AreNotEqual(id, detection.Id);
            Assert.AreNotEqual(name, detection.Name);
            Assert.AreNotEqual(start, detection.Start);
            Assert.AreNotEqual(length, detection.Length);
            Assert.AreNotEqual(metadata, detection.Metadata);
            Assert.AreNotEqual(start + length, detection.End);
            Assert.AreNotEqual(rotationPeriod, detection.RotationPeriod);
            Assert.AreNotEqual(sha256Hash, detection.RedactionToken);
        }

        [TestMethod]
        public void Detection_UniqueHashCodesGeneratedWhenPropertiesChange()
        {
            string id = $"{Guid.NewGuid()}";
            string name = $"{Guid.NewGuid()}";
            string sha256Hash = $"{Guid.NewGuid()}";
            string redactionToken = $"{Guid.NewGuid()}";

            var metadata = (DetectionMetadata)0B_11111;
            int start = (int)DateTime.UtcNow.Ticks % 99;
            int length = (int)DateTime.UtcNow.Ticks % 99;
            TimeSpan rotationPeriod = TimeSpan.FromSeconds(DateTime.UtcNow.Second);

            var detection = new Detection
            {
                Id = id,
                Name = name,
                Start = start,
                Length = length,
                Metadata = metadata,
                RotationPeriod = rotationPeriod,
                RedactionToken = sha256Hash,
            };

            var emptyDefaultDetection = new Detection();

            Assert.AreNotEqual(emptyDefaultDetection.GetHashCode(), detection.GetHashCode());

            int previousHashCode = detection.GetHashCode();
            detection.Id = default;
            Assert.AreNotEqual(detection.GetHashCode(), previousHashCode);

            previousHashCode = detection.GetHashCode();
            detection.Name = default;
            Assert.AreNotEqual(detection.GetHashCode(), previousHashCode);

            previousHashCode = detection.GetHashCode();
            detection.Start = default;
            Assert.AreNotEqual(detection.GetHashCode(), previousHashCode);

            previousHashCode = detection.GetHashCode();
            detection.Length = default;
            Assert.AreNotEqual(detection.GetHashCode(), previousHashCode);

            previousHashCode = detection.GetHashCode();
            detection.Metadata = default;
            Assert.AreNotEqual(detection.GetHashCode(), previousHashCode);

            previousHashCode = detection.GetHashCode();
            detection.RotationPeriod = default;
            Assert.AreNotEqual(detection.GetHashCode(), previousHashCode);

            previousHashCode = detection.GetHashCode();
            detection.RedactionToken = default;
            Assert.AreNotEqual(detection.GetHashCode(), previousHashCode);

            // At this point, we should have reset our entire object to its
            // default state and GetHashCode() should be equivalent.
        }

        [TestMethod]
        public void Detection_EqualComparisonUpdateWhenPropertiesChange()
        {
            var currentDetection = new Detection();
            var emptyDefaultDetection = new Detection();

            Assert.AreEqual(emptyDefaultDetection, currentDetection);

            var previousDetection = new Detection(currentDetection);
            Assert.AreEqual(currentDetection, previousDetection);

            currentDetection.Id = $"{Guid.NewGuid()}"; ;
            Assert.AreNotEqual(currentDetection, previousDetection);

            previousDetection = new Detection(currentDetection);
            Assert.AreEqual(currentDetection, previousDetection);

            currentDetection.Start = (int)DateTime.UtcNow.Ticks % 99;
            Assert.AreNotEqual(currentDetection, previousDetection);

            previousDetection = new Detection(currentDetection);
            Assert.AreEqual(currentDetection, previousDetection);

            currentDetection.Length = (int)DateTime.UtcNow.Ticks % 99;
            Assert.AreNotEqual(currentDetection, previousDetection);

            previousDetection = new Detection(currentDetection);
            Assert.AreEqual(currentDetection, previousDetection);

            currentDetection.Metadata = (DetectionMetadata)0B_11111;
            Assert.AreNotEqual(currentDetection, previousDetection);

            previousDetection = new Detection(currentDetection);
            Assert.AreEqual(currentDetection, previousDetection);

            currentDetection.RotationPeriod = TimeSpan.FromSeconds(DateTime.UtcNow.Second);
            Assert.AreNotEqual(currentDetection, previousDetection);

            previousDetection = new Detection(currentDetection);
            Assert.AreEqual(currentDetection, previousDetection);

            currentDetection.RedactionToken = $"{Guid.NewGuid()}"; ;
            Assert.AreNotEqual(currentDetection, previousDetection);

            previousDetection = new Detection(currentDetection);
            Assert.AreEqual(currentDetection, previousDetection);

            // At this point, we should have reset our entire object to its
            // default state and GetHashCode() should be equivalent.
        }
    }
}