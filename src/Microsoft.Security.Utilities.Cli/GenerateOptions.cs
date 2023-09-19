// Copyright (c) Microsoft. All rights reserved.
#nullable disable
using CommandLine;
using System.Globalization;

namespace Microsoft.Security.Utilities.Cli
{
    [Verb("generate", HelpText = "Generate an identifiable key.")]
    public class GenerateOptions
    {
        [Option(
            "signature",
            Required = true,
            HelpText = "A fixed signature to inject into the generated key).")]
        public string FixedSignature { get; set; }

        [Option(
            "seed",
            Required = true,
            HelpText = "A checksum seed used to differentiate checksum space derived from random bytes of the key.")]
        public string ChecksumSeedText { get; set; }

        [Option(
            "url-safe",
            Required = false,
            HelpText = "Indicates whether the generated base64-encoded key should be URL-safe (preferring '-' and '_' as special characters.")]
        public ulong UrlSafe { get; set; }

        [Option(
            "length",
            Required = false,
            Default = (uint)39,
            HelpText = "The key length in bytes.")]
        public uint LengthInBytes { get; set; }

        [Option(
            "count",
            Required = false,
            Default = (uint)1,
            HelpText = "The count of keys to generate.")]
        public uint Count { get; set; }

        public ulong ChecksumSeed
        {
            get
            {
                if (!ChecksumSeedText.StartsWith("0x") && !ChecksumSeedText.StartsWith("0X"))
                {
                    throw new ArgumentException("Please provide the seed in hex string format.", "seed");
                }

                if (ulong.TryParse(ChecksumSeedText.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var number))
                {
                    return number;
                }
                else
                {
                    throw new ArgumentException("The provided seed is invalid.", "seed");
                }
            }
        }

    }
}