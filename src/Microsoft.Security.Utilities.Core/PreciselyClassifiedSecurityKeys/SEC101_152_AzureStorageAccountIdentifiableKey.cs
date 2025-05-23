﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Security.Utilities
{
    public class AzureStorageAccountIdentifiableKey : Azure64ByteIdentifiableKey
    {
        public AzureStorageAccountIdentifiableKey() : base(IdentifiableMetadata.AzureStorageSignature)
        {
            Id = "SEC101/152";
            Name = nameof(AzureStorageAccountIdentifiableKey);
            Label = "an Azure storage account access key";
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureStorageAccountChecksumSeed };
        }

        public override Version CreatedVersion => Releases.Version_01_04_02;

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            string sampleKey = string.Empty;

            foreach (string example in base.GenerateTruePositiveExamples())
            {
                sampleKey = example;
                yield return example;
            }

            var legacyStorageAccountKey = new AzureStorageAccountLegacyCredentials();

            // The legacy storage account key rule requires more context in the scan contents,
            // specifically, it looks for a key embedded in a connection string. We have had
            // misses previously due to mismanaging delimiters around the identifiable key
            // rules, so we will obtain the legacy rule patterns, replace their secret with
            // an identifiable one, and ensure this rule continues to function against a very
            // typical expression of this credential kind.
            foreach (string example in legacyStorageAccountKey.GenerateTruePositiveExamples())
            {
                string standaloneSecret =
                        CachedDotNetRegex.Instance.Matches(example,
                                                           legacyStorageAccountKey.Pattern,
                                                           captureGroup: "refine").First().Value;

                string generatedExample = example.Replace(standaloneSecret, sampleKey);
                yield return generatedExample;
            }
        }
    }
}
