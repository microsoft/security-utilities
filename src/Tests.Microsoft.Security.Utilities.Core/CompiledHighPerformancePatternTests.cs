// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace Tests.Microsoft.Security.Utilities.Core;

[TestClass]
public class CompiledHighPerformancePatternTests
{
#if DEBUG
    // TODO: Use Roslyn generator: https://github.com/microsoft/security-utilities/issues/152
    [TestMethod]
    public void CompiledHighPerformancePattern_EnsureCodeGenIsUpToDate()
    {
        string expected = CompiledHighPerformancePattern.GenerateAdditionalCode();
        string path = GetGeneratedFilePath();
        string actual = File.ReadAllText(path);

        // Use EndsWith because the file also has a comment at the top. Also,
        // ignore whitespace at the end of both sides.
        if (!actual.TrimEnd().EndsWith(expected.TrimEnd(), StringComparison.Ordinal))
        {
            Assert.Fail($"""
                        The generated code in '${path}' is out-of-date.
                        To regenerate:
                          - Open '{Path.ChangeExtension(path, ".tt")}' in Visual Studio
                          - Select Debug configuration.
                          - Hit Ctrl+S to save.
                        """);
        }
    }

    private static string GetGeneratedFilePath([CallerFilePath] string path = "")
    {
        path = Path.GetDirectoryName(path);
        path = Path.Combine(path,
                            "..", 
                            "Microsoft.Security.Utilities.Core", 
                            $"{nameof(CompiledHighPerformancePattern)}.Generated.cs");
        return path;
    }
#endif
}
