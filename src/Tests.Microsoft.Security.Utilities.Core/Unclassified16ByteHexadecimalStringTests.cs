// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.Linq;

namespace Microsoft.Security.Utilities.Core
{
    [TestClass]
    public class Unclassified16ByteHexadecimalStringTests
    {

        [TestMethod]
        public void Unclassified16ByteHexadecimalString_ValidInput()
        {
            var classifier = new Unclassified16ByteHexadecimalString();
            string validInput = "0123456789abcdef0123456789abcdef";
            
            var result = classifier.GetMatchIdAndName(validInput);

            Assert.IsNotNull(result);
            Assert.AreEqual("SEC000/002", result.Item1);
            Assert.AreEqual("Unclassified16ByteHexadecimalString", result.Item2);

            var detection =
                classifier.GetDetections(validInput, generateCrossCompanyCorrelatingIds: false).FirstOrDefault();

            Assert.IsNotNull(detection);
            Assert.AreEqual("SEC000/002", detection.Id);
        }
    }
}
