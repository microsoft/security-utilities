// Copyright (c) Microsoft. All rights reserved.

#nullable disable


namespace Microsoft.Security.Utilities.Cli
{
    internal class ScanCommand
    {
        public ScanCommand()
        {
        }

        internal int Run(ScanOptions options)
        {
            string path = options.Path;

            var scan = new IdentifiableScan();
            var buffer = new byte[85 * 1024];
            var text = new byte[256];

            using (var file = File.OpenRead(path))
            {
                scan.Start();

                for (;;)
                {
                    var read = file.Read(buffer, 0, buffer.Length);

                    if (read == 0)
                    {
                        break;
                    }

                    scan.Scan(buffer, read);
                }

                if (scan.PossibleMatches == 0)
                {
                    Console.WriteLine("None found.");
                }

                for (var i = 0; i < scan.PossibleMatches; ++i)
                {
                    UInt64 start, len;

                    if (scan.GetPossibleMatchRange(
                        i,
                        out start,
                        out len))
                    {
                        file.Seek((long)start, SeekOrigin.Begin);

                        var remaining = (int)len;
                        var copied = 0;

                        while (remaining > 0)
                        {
                            var read = file.Read(buffer, (int)copied, (int)remaining);

                            if (read == 0)
                            {
                                break;
                            }

                            copied += read;
                            remaining -= read;
                        }

                        long textLength;

                        var type = scan.CheckPossibleMatchRange(
                            i,
                            buffer,
                            copied,
                            text,
                            out textLength);

                        if (type != IdentifiableScan.MatchType.None)
                        {
                            var secret = System.Text.Encoding.UTF8.GetString(text, 0, (int)textLength);

                            Console.WriteLine("Found {0} ('{1}') at position {2}", type, secret, start);
                        }
                    }
                }
            }

            return 0;
        }
    }
}
