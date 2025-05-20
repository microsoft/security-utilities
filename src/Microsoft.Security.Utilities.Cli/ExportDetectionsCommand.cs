// Copyright (c) Microsoft. All rights reserved.

#nullable disable

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;

namespace Microsoft.Security.Utilities.Cli
{
    public class ExportDetectionsCommand
    {
        public ExportDetectionsCommand()
        {
        }

        internal int Run(ExportDetectionsOptions options)
        {
            WriteJson(options,
                      "UnclassifiedPotentialSecurityKeys.json",
                      WellKnownRegexPatterns.UnclassifiedPotentialSecurityKeys);

            WriteJson(options,
                     "PreciselyClassifiedSecurityKeys.json",
                      WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys);

            foreach (DetectionMetadata precision in new[] { DetectionMetadata.HighConfidence, DetectionMetadata.MediumConfidence, DetectionMetadata.LowConfidence })
            {
                WriteJson(options,
                          $"{precision}SecurityModels.json",
                          WellKnownRegexPatterns.SecretStoreClassificationDetections
                         .Where(d => d.DetectionMetadata.HasFlag(precision)));
            }

            return 0;
        }

        private static void WriteJson(ExportDetectionsOptions options, string name, IEnumerable<RegexPattern> patterns)
        {
            string outputFileName = Path.Combine(options.OutputDirectory, name);

            var settings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                Converters = { new StringEnumConverter() },
            };

            string json = JsonConvert.SerializeObject(patterns, settings);
            File.WriteAllText(outputFileName, json);
        }
    }
}