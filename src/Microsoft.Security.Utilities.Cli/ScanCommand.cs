// Copyright (c) Microsoft. All rights reserved.

#nullable disable

namespace Microsoft.Security.Utilities.Cli
{
    public class ScanCommand
    {
        public ScanCommand()
        {
        }

        internal int Run(ScanOptions options)
        {
            if (options.Input == null && options.StringInput == null)
            {
                Console.WriteLine("No input specified.");
                return 1;
            }
            else if (options.Input != null && options.StringInput != null)
            {
                Console.WriteLine("Both input and string-input specified. Please specify only one.");
                return 1;
            }
            else if (options.Input != null)
            {
                return ProcessInputFile(options);
            }
            else
            {
                return ProcessInputString(options);
            }
        }

        internal int ProcessInputFile(ScanOptions options)
        {
            string input = options.Input;

            var scan = new IdentifiableScan(WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys, generateCorrelatingIds: true);

            string directory = Path.GetDirectoryName(input);
            string fileSpecifier = Path.GetFileName(input);

            SearchOption searchOption = options.Recurse
                ? SearchOption.AllDirectories
                : SearchOption.TopDirectoryOnly;

            foreach (string path in Directory.GetFiles(directory, fileSpecifier, searchOption))
            {
                string fileName = Path.GetFileName(path);
                string contents = File.ReadAllText(path);
                bool foundAtLeastOne = false;

                foreach (var detection in scan.DetectSecrets(contents))
                {
                    foundAtLeastOne = true;
                    Console.WriteLine($"{fileName} ({detection.Start},{detection.End}): {detection.Moniker} : {Detections.Format(detection, contents)}");
                }

                if (!foundAtLeastOne)
                {
                    Console.WriteLine($"None found: {path}");
                    continue;
                }
            }

            return 0;
        }

        internal int ProcessInputString(ScanOptions options)
        {
            var scan = new IdentifiableScan(WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys, generateCorrelatingIds: true);

            bool foundAtLeastOne = false;

            string contents = options.StringInput;
            foreach (var detection in scan.DetectSecrets(contents))
            {
                foundAtLeastOne = true;
                Console.WriteLine($"Offset {detection.Start},{detection.End} : {detection.Moniker} : {Detections.Format(detection, contents)}");
            }

            if (!foundAtLeastOne)
            {
                Console.WriteLine($"None found in input string");
            }

            return 0;
        }
    }
}
