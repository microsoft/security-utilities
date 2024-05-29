// Copyright (c) Microsoft. All rights reserved.
#nullable disable
using CommandLine;

namespace Microsoft.Security.Utilities.Cli
{
    [Verb("redact", HelpText = "Redact secrets from files.")]
    public class RedactOptions
    {
        [Option(
            "input",
            Required = true,
            HelpText = "An input directory that contains one or more files from which secrets should be removed.")]
        public string Input { get; set; }

        [Option(
            "output",
            HelpText = "An optional output directory to which redacted content should be written.")]
        public string Output { get; set; }
    }
}