// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureCacheForRedisIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureCacheForRedisIdentifiableKey()
        {
            Id = "SEC101/154";
            Name = nameof(AzureCacheForRedisIdentifiableKey);
        }

        public override ISet<string> Signatures => IdentifiableMetadata.AzureCacheForRedisSignature.ToSet();

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureCacheForRedisChecksumSeed};

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
            while (true)
            {
                string key =
                    IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureCacheForRedisChecksumSeed,
                                                                  32,
                                                                  IdentifiableMetadata.AzureCacheForRedisSignature);

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
