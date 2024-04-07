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
            HelpText = "A specifier that resolves to one or more files from which secrets should be removed.")]
        public string Input { get; set; }
    }
}