using System;
using System.Reflection;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities
{
    public abstract class MarvinShared
    {
        /// <summary>
        /// A random seed value used by the tests referenced below.
        /// </summary>
        public const ulong Seed0 = 0x004fb61a001bdbcc;

        /// <summary>
        /// A random seed value used by the tests referenced below.
        /// </summary>
        public const ulong Seed1 = 0x804fb61a001bdbcc;

        /// <summary>
        /// A random seed value used by the tests referenced below.
        /// </summary>
        public const ulong Seed2 = 0x804fb61a801bdbcc;

        /// <summary>
        /// In the spirit of cross-checking, these tests are pulled from a non-Microsoft
        /// Marvin32 implementation. This implementation, per Niels Ferguson is not considered
        /// completely compliant/correct and so it should not be used. But the simple test
        /// cases here do result in matching output.
        /// https://github.com/skeeto/marvin32/blob/21020faea884799879492204af70414facfd27e9/marvin32.c#L112
        /// </summary>
        public static readonly TestCase[] TestCases = new[]
        {
            new TestCase { Seed = Seed0, Text = string.Empty,  Checksum = 0x30ed35c100cd3c7d},
            new TestCase { Seed = Seed0, Text = "\xaf",  Checksum = 0x48e73fc77d75ddc1},
            new TestCase { Seed = Seed0, Text = "\xe7\x0f",  Checksum = 0xb5f6e1fc485dbff8},
            new TestCase { Seed = Seed0, Text = "\x37\xf4\x95",  Checksum = 0xf0b07c789b8cf7e8},
            new TestCase { Seed = Seed0, Text = "\x86\x42\xdc\x59",  Checksum = 0x7008f2e87e9cf556},
            new TestCase { Seed = Seed0, Text = "\x15\x3f\xb7\x98\x26",  Checksum = 0xe6c08c6da2afa997},
            new TestCase { Seed = Seed0, Text = "\x09\x32\xe6\x24\x6c\x47",  Checksum = 0x6f04bf1a5ea24060},
            new TestCase { Seed = Seed0, Text = "\xab\x42\x7e\xa8\xd1\x0f\xc7",  Checksum = 0xe11847e4f0678c41},

            new TestCase { Seed = Seed1, Text = string.Empty,  Checksum = 0x10a9d5d3996fd65d},
            new TestCase { Seed = Seed1, Text = "\xaf",  Checksum = 0x68201f91960ebf91},
            new TestCase { Seed = Seed1, Text = "\xe7\x0f",  Checksum = 0x64b581631f6ab378},
            new TestCase { Seed = Seed1, Text = "\x37\xf4\x95",  Checksum = 0xe1f2dfa6e5131408},
            new TestCase { Seed = Seed1, Text = "\x86\x42\xdc\x59",  Checksum = 0x36289d9654fb49f6},
            new TestCase { Seed = Seed1, Text = "\x15\x3f\xb7\x98\x26",  Checksum = 0x0a06114b13464dbd},
            new TestCase { Seed = Seed1, Text = "\x09\x32\xe6\x24\x6c\x47",  Checksum = 0xd6dd5e40ad1bc2ed},
            new TestCase { Seed = Seed1, Text = "\xab\x42\x7e\xa8\xd1\x0f\xc7",  Checksum = 0xe203987dba252fb3},

            new TestCase { Seed = Seed2, Text = "\x00",  Checksum = 0xa37fb0da2ecae06c},
            new TestCase { Seed = Seed2, Text = "\xff",  Checksum = 0xfecef370701ae054},
            new TestCase { Seed = Seed2, Text = "\x00\xff",  Checksum = 0xa638e75700048880},
            new TestCase { Seed = Seed2, Text = "\xff\x00",  Checksum = 0xbdfb46d969730e2a},
            new TestCase { Seed = Seed2, Text = "\xff\x00\xff",  Checksum = 0x9d8577c0fe0d30bf},
            new TestCase { Seed = Seed2, Text = "\x00\xff\x00",  Checksum = 0x4f9fbdde15099497},
            new TestCase { Seed = Seed2, Text = "\x00\xff\x00\xff",  Checksum = 0x24eaa279d9a529ca},
            new TestCase { Seed = Seed2, Text = "\xff\x00\xff\x00",  Checksum = 0xd3bec7726b057943},
            new TestCase { Seed = Seed2, Text = "\xff\x00\xff\x00\xff",  Checksum = 0x920b62bbca3e0b72},
            new TestCase { Seed = Seed2, Text = "\x00\xff\x00\xff\x00",  Checksum = 0x1d7ddf9dfdf3c1bf},
            new TestCase { Seed = Seed2, Text = "\x00\xff\x00\xff\x00\xff",  Checksum = 0xec21276a17e821a5},
            new TestCase { Seed = Seed2, Text = "\xff\x00\xff\x00\xff\x00",  Checksum = 0x6911a53ca8c12254},
            new TestCase { Seed = Seed2, Text = "\xff\x00\xff\x00\xff\x00\xff",  Checksum = 0xfdfd187b1d3ce784},
            new TestCase { Seed = Seed2, Text = "\x00\xff\x00\xff\x00\xff\x00",  Checksum = 0x71876f2efb1b0ee8},
        };

        /// <summary>
        /// Retrieve .NET's Marvin class, if available.
        /// </summary>
        /// <returns>typeof(System.Marvin), if it is available.</returns>
        public static Type GetMarvinType()
        {
            return typeof(object).Assembly.GetType("System.Marvin");
        }

        /// <summary>
        /// Retrieve the random seed that is used by .NET's Marvin class, if available.
        /// </summary>
        /// <returns>The current random value that seeds the .NET GetHashCode Marvin checksum computation.</returns>
        public static ulong GetDotNetCurrentMarvinDefaultSeed()
        {
            Type marvinType = GetMarvinType();

            if (marvinType == null)
            {
                throw new InvalidOperationException();
            }

            FieldInfo fi = null;
            foreach (FieldInfo marvinField in marvinType.GetFields(BindingFlags.NonPublic | BindingFlags.Static))
            {
                if (marvinField.Name.Contains("DefaultSeed"))
                {
                    fi = marvinField;
                    break;
                }
            }

            Assert.IsNotNull(fi);
            return (ulong)fi.GetValue(null);
        }
    }
}
