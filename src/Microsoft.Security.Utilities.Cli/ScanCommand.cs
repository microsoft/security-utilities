// Copyright (c) Microsoft. All rights reserved.

#nullable disable

namespace Microsoft.Security.Utilities.Cli
{
    public class ScanCommand
    {
        private static IEnumerable<RegexPattern> RegexPatterns()
        {
            foreach (RegexPattern regexPattern in WellKnownRegexPatterns.HighConfidenceSecurityModels)
            {
                if (regexPattern is IIdentifiableKey)
                {
                    yield return regexPattern;
                }
            }
        }
        public ScanCommand()
        {
        }

        internal int Run(ScanOptions options)
        {
            string input = options.Input;

            var scan = new IdentifiableScan(RegexPatterns(), generateCorrelatingIds: true);

            string directory = Path.GetDirectoryName(input);
            string fileSpecifier = Path.GetFileName(input);

            SearchOption searchOption = options.Recurse
                ? SearchOption.AllDirectories
                : SearchOption.TopDirectoryOnly;

            foreach (string path in Directory.GetFiles(directory, fileSpecifier, searchOption))
            {
                using (var file = File.OpenRead(path))
                {
                    bool foundAtLeastOne = false;

                    foreach (var detection in scan.DetectSecrets(file))
                    {
                        foundAtLeastOne = true;
                        Console.WriteLine("Found {0} ('{1}') at position {2}", detection.Id, detection.RedactionToken, detection.Start + detection.Length);
                    }

                    if (!foundAtLeastOne)
                    {
                        Console.WriteLine($"None found: {path}");
                        continue;
                    }
                }
            }

            return 0;
        }
    }
}
