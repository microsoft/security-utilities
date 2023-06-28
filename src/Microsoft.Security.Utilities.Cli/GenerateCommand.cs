// Copyright (c) Microsoft. All rights reserved.

#nullable disable

namespace Microsoft.Security.Utilities.Cli
{
    internal class GenerateCommand
    {
        public GenerateCommand()
        {
        }

        internal int Run(GenerateOptions options)
        {
            for (int i = 0; i< options.Count; i++) 
            {
                string key =
                    IdentifiableSecrets.GenerateStandardBase64Key(options.ChecksumSeed,
                                                                  options.LengthInBytes,
                                                                  options.FixedSignature);

                Console.WriteLine(key);
            }

            return 0;
        }
    }
}