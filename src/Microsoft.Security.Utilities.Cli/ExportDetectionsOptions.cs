// Copyright (c) Microsoft. All rights reserved.
#nullable disable
using CommandLine;

namespace Microsoft.Security.Utilities.Cli
{
    [Verb("export", HelpText = "Exports all rules to JSON representation")]
    public class ExportDetectionsOptions
    {
        [Option(
            "output",
            Required = true,
            HelpText = "The directory to which all output should be persisted.")]
        public string OutputDirectory { get; set; }
    }
}