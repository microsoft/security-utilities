// Copyright (c) Microsoft. All rights reserved.

using CommandLine;

namespace Microsoft.Security.Utilities.Cli
{
    class Program
    {
        public static int Main(string[] args)
        {
            try
            {
                return Parser.Default.ParseArguments<
                    RedactOptions,
                    GenerateOptions,
                    ExportDetectionsOptions,
		    ScanOptions> (args)
                  .MapResult(
                    (RedactOptions options) => new RedactCommand().Run(options),
                    (GenerateOptions options) => new GenerateCommand().Run(options),
                    (ExportDetectionsOptions options) => new ExportDetectionsCommand().Run(options),
                    (ScanOptions options) => new ScanCommand().Run(options),
                    _ => 1);
            }
            catch (Exception e)
            {
                Console.WriteLine (e);
                return 1;
            }
        }
    }
}
