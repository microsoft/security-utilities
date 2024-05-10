// Copyright (c) Microsoft. All rights reserved.

#nullable disable


namespace Microsoft.Security.Utilities.Cli
{
    internal class RedactCommand
    {
        public RedactCommand()
        {
        }

        internal int Run(RedactOptions options)
        {
            string input = options.Input;
            string output = options.Output;
            
            var secretMasker = new SecretMasker(WellKnownRegexPatterns.HighConfidenceMicrosoftSecurityModels,
                                                generateCorrelatingIds: true);

            secretMasker.AddPatterns(WellKnownRegexPatterns.LowConfidencePotentialSecurityKeys);

            if (!string.IsNullOrEmpty(output) && !Directory.Exists(output))
            {
                Directory.CreateDirectory(output);
            }

            foreach (string file in Directory.GetFiles(input, "*", SearchOption.AllDirectories)) 
            { 
                string inputText = File.ReadAllText(file);
                string redactedText = secretMasker.MaskSecrets(inputText);

                string outputFilePath = string.IsNullOrEmpty(output)
                    ? file
                    : Path.Combine(output, file.Substring(input.Length));

                if (!object.ReferenceEquals(inputText, redactedText))
                {
                    File.WriteAllText(outputFilePath, redactedText);
                }
            }
            
            return 0;
        }
    }
}