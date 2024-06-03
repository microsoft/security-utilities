// Copyright (c) Microsoft. All rights reserved.

#nullable disable

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;


namespace Microsoft.Security.Utilities.Cli
{
    public class ExportDetectionsCommand
    {
        public ExportDetectionsCommand()
        {
        }

        internal int Run(ExportDetectionsOptions options)
        {
            string outputDirectory = options.OutputDirectory;
            string outputFileName;

            outputFileName = Path.Combine(outputDirectory, "PreciselyClassifiedSecurityKeys.json");
            string json = JsonConvert.SerializeObject(WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys,
                                                      Formatting.Indented,
                                                      new StringEnumConverter());
            File.WriteAllText(outputFileName, json);

            outputFileName = Path.Combine(outputDirectory, "UnclassifiedPotentialSecurityKeys.json");
            json = JsonConvert.SerializeObject(WellKnownRegexPatterns.UnclassifiedPotentialSecurityKeys,
                                                      Formatting.Indented,
                                                      new StringEnumConverter());
            File.WriteAllText(outputFileName, json);

            return 0;
        }
    }
}