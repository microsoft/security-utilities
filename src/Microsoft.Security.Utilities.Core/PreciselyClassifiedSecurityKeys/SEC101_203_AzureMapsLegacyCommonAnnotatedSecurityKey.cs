// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureMapsLegacyCommonAnnotatedSecurityKey : LegacyCommonAnnotatedSecurityAccessKey
    {
        public AzureMapsLegacyCommonAnnotatedSecurityKey() : base()
        {
            Id = "SEC101/203";
            Name = nameof(AzureMapsLegacyCommonAnnotatedSecurityKey);
            Label = "an Azure Maps legacy common annotated security key";
        }

        protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureMaps;

        public override Version CreatedVersion => Releases.Unreleased;
    }
}
