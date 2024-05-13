// Copyright (c) Microsoft. All rights reserved.
#nullable disable
using CommandLine;

namespace Microsoft.Security.Utilities.Cli
{
    [Verb("scan", HelpText = "Scan identifiable secrets in files.")]
    public class ScanOptions
    {
        [Option(
            "path",
            Required = true,
            HelpText = "A path to a file to scan for identifiable secrets.")]
        public string Path { get; set; }
    }
}
