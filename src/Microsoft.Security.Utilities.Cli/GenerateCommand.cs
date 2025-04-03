// Copyright (c) Microsoft. All rights reserved.

#nullable disable

namespace Microsoft.Security.Utilities.Cli
{
    public class GenerateCommand
    {
        internal int Run(GenerateOptions options)
        {
            for (int i = 0; i < options.Count; i++)
            {
                string key =
                    IdentifiableSecrets.GenerateBase64KeyHelper(options.ChecksumSeed,
                                                                options.LengthInBytes,
                                                                options.FixedSignature,
                                                                options.UrlSafe);


                Console.WriteLine(key);
            }

            return 0;
        }
    }
}