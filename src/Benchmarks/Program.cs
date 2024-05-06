
using BenchmarkDotNet.Running;

using Benchmarks;

new RegexEngineDetectionBenchmarks().RE2();
//var summary = BenchmarkRunner.Run<RegexEngineDetectionBenchmarks>();