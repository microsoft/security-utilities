using System;

using Microsoft.Security.Utilities;

namespace SecurityUtilitiesApiUtilizationExample
{
    internal class Program
    {
        static void Main(string[] args)
        {
            int iterations = 10;

            var masker = new IdentifiableScan(WellKnownRegexPatterns.HighConfidenceMicrosoftSecurityModels,
                                              generateCorrelatingIds: false);

            foreach (var pattern in WellKnownRegexPatterns.HighConfidenceSecurityModels)
            {
                var identifiable = pattern as IIdentifiableKey;
                if (identifiable == null) { continue; }

                foreach (ulong seed in identifiable.ChecksumSeeds)
                {
                    for (int i = 0; i < iterations; i++)
                    {
                        foreach (string signature in identifiable.Signatures)
                        {
                            string key = IdentifiableSecrets.GenerateStandardBase64Key(seed,
                                                                                     identifiable.KeyLength,
                                                                                     signature);

                            masker.DetectSecrets(key);
                        }
                    }
                }
            }

            Console.WriteLine("Test for Microsoft.Security.Utilities.Core nuget completed");
        }
    }
}
     
    