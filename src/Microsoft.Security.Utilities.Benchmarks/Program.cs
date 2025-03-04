
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/*
 * To run these benchmarks, navigate to the benchmark source directory and use
 * one of the following commands, depending on which target framework you want
 * to benchmark:
 *
 *   dotnet run -c Release -f net8.0 dotnet run -c Release -f net472
 *
 * This will prompt you on which benchmarks to run.
 *
 * You can also specify a glob filter to select without prompts:
 *
 *   dotnet run -c Release -f net8.0 --filter *Hash*
 *
 * Or pass other options to BenchmarkDotNet. For help:
 *
 *   dotnet run -c Release -f net8.0 -- --help
 *
 * NOTE: '--' delimiter ensures --help goes to BenchmarkDotNet, not dotnet.
 *
 * To debug these benchmarks, you can set this project as the startup project in
 * Each benchmark will be run a few times without measuring anything.git 
 */

using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;

using Microsoft.Security.Utilities.Benchmarks;

bool debug = false;
#if DEBUG 
debug = true;
#else
debug = System.Diagnostics.Debugger.IsAttached;
#endif

if (debug)
{
    DebugBenchmarkRunner.Run();
    return;
}

BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
