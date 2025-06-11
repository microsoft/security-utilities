// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureCacheForRedisIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureCacheForRedisIdentifiableKey() : base(IdentifiableMetadata.AzureCacheForRedisSignature)
        {
            Id = "SEC101/154";
            Name = nameof(AzureCacheForRedisIdentifiableKey);
            Label = Resources.Label_SEC101_154_AzureCacheForRedisIdentifiableKey;
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureCacheForRedisChecksumSeed };
        }

        public override Version CreatedVersion => Releases.Version_01_04_10;

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if (!IdentifiableMetadata.IsAzureCacheForRedisIdentifiableKey(match))
            {
                return null;
            }

            return base.GetMatchIdAndName(match);
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            foreach (string key in base.GenerateTruePositiveExamples())
            {
                if (key.Contains("/") || key.Contains("+"))
                {
                    continue;
                }
                yield return key;
                break;
            }
        }
    }
}
