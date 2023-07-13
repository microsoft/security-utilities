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
                    GenerateOptions>(args)
                  .MapResult(
                    (GenerateOptions options) => new GenerateCommand().Run(options),
                    _ => 1);
            }
            catch (Exception)
            {
                return 1;
            }
        }
    }
}