// Copyright (c) Microsoft. All rights reserved.

using CommandLine;

namespace Microsoft.Security.Utilities.Cli
{
    class Program
    {
        public static int Main(string[] args)
        {

            string key = "BYe4kr49oDWdXGKupTMPsriHvAnPok6drMlJygXuiBwaoYd1EDNM6mULm6F5GDEO5sGBGc4korpNO1BvASuYW5==";
            key = "86Sn4oDyr7quvTHa2PvLT5eF585be5sev7JL92oWmXunZZpPSKlmDUuOoOiCzIueZFG3y6jpzm7Wz6jlmGfRVp==";
            string signatured = "z6jl";
            bool isValid = IdentifiableSecrets.TryValidateCommonAnnotatedKey(key, signatured);
            Console.WriteLine(isValid);

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
