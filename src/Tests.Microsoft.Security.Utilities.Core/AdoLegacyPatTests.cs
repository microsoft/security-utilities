// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace Microsoft.Security.Utilities.Core
{
    [TestClass]
    public class AdoLegacyPatTests
    {
        [TestMethod]
        public void AdoLegacyPat_InvalidBase32Input()
        {
            var classifier = new AdoLegacyPat();
            string invalidInput = "=22222222222222222222222222";
            Tuple<string, string> result = classifier.GetMatchIdAndName(invalidInput);
            Assert.IsNull(result);
        }
    }
}
