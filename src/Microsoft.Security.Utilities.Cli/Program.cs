// Copyright (c) Microsoft. All rights reserved.

using CommandLine;

namespace Microsoft.Security.Utilities.Cli
{
    class Program
    {
        public static int Main(string[] args)
        {

            int iterations = 10;
            for (byte i = 0; i < iterations; i++)
            {
                bool customerManagedKey = false;
                ulong checksumSeed = (ulong)Guid.NewGuid().ToString().GetHashCode();
                string signature = "AZSE";
                string key = IdentifiableSecrets.GenerateCommonAnnotatedKey(checksumSeed,
                                                                            signature,
                                                                            customerManagedKey,
                                                                            2,
                                                                            1,
                                                                            27,
                                                                            4);
                
                if (!IdentifiableSecrets.TryValidateCommonAnnotatedKey(key, checksumSeed, signature, customerManagedKey))
                {
                    throw new InvalidOperationException("Generated key is invalid");
                }

                Console.WriteLine(key);
            }

            try
            {
                return Parser.Default.ParseArguments<
                    GenerateOptions,
                    ExportDetectionsOptions> (args)
                  .MapResult(
                    (GenerateOptions options) => new GenerateCommand().Run(options),
                    (ExportDetectionsOptions options) => new ExportDetectionsCommand().Run(options),
                    _ => 1);
            }
            catch (Exception)
            {
                return 1;
            }
        }
    }
}