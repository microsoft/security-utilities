// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;

using FluentAssertions;
using FluentAssertions.Execution;

using Microsoft.Security.Utilities.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities
{
    [TestClass, ExcludeFromCodeCoverage]
    public class UnclassifiedLegacyCommonAnnotatedSecurityKeyTests
    {
        [TestMethod]
        public void CommonAnnotatedKey_TryCreateWithNonCaskSecret()
        {
            using var _ = new AssertionScope();

            foreach (bool longForm in new[] { true, false })
            {
                string signature = "APIM";

                string caskSecret = IdentifiableSecrets.GenerateCommonAnnotatedKey(signature, customerManagedKey: true, null, null, longForm);
                string legacySecret = Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Trim('=');

                foreach (string secret in new[] { caskSecret, legacySecret })
                {
                    var action = () => LegacyCommonAnnotatedSecurityKey.TryCreate(secret, out LegacyCommonAnnotatedSecurityKey cask);
                    action.Should().NotThrow(because: "TryCreate should never throw");
                }
            }
        }

        [TestMethod]
        public void LegacyCommonAnnotatedKey_AllProviderSignaturesPresent()
        {
            foreach (FieldInfo fi in typeof(LegacyCaskProviderSignatures).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                if (fi.Name == nameof(LegacyCaskProviderSignatures.All))
                {
                    continue;
                }

                string fieldValue = (string)fi.GetValue(null);

                LegacyCaskProviderSignatures.All.Contains(fieldValue).Should().BeTrue(because: $"'LegacyCaskProviderSignatures.All' should contain 'LegacyCaskProviderSignatures.{fi.Name}' value of '{fieldValue}'");
            }

            LegacyCaskProviderSignatures.All.Should().NotBeEmpty(because: "LegacyCaskProviderSignatures should not be empty");
        }
    }
}
