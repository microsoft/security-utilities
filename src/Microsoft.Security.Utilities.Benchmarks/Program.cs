
using BenchmarkDotNet.Running;

using Microsoft.Security.Utilities.Benchmarks;

//new RegexEngineDetectionBenchmarks().UseIdentifiableScan();
//new RegexEngineDetectionBenchmarks().UseCachedDotNet();
//new RegexEngineDetectionBenchmarks().UseRE2();

var summary = BenchmarkRunner.Run<RegexEngineDetectionBenchmarks>();