#include "evp/digest/Digests.h"
#include <string>
#include <catch2/catch.hpp>

//https://www.di-mgt.com.au/sha_testvectors.html#testvectors

static std::vector<uint8_t> calcHash(const std::string& input)
{
    return EvpDigest::CalcHash<Sha256Digest>((const uint8_t*)input.c_str(), input.size());
}

TEST_CASE("Sha256", "[digest][evp]")
{
    {
        std::string input = "abc";
        std::vector<uint8_t> expected= {0xba, 0x78, 0x16, 0xbf,
                                        0x8f, 0x01, 0xcf, 0xea,
                                        0x41, 0x41, 0x40, 0xde,
                                        0x5d, 0xae, 0x22, 0x23,
                                        0xb0, 0x03, 0x61, 0xa3,
                                        0x96, 0x17, 0x7a, 0x9c,
                                        0xb4, 0x10, 0xff, 0x61,
                                        0xf2, 0x00, 0x15, 0xad};

        CHECK(calcHash(input) == expected);
    }

    {
        std::string input = "";
        std::vector<uint8_t> expected= {0xe3, 0xb0, 0xc4, 0x42,
                                        0x98, 0xfc, 0x1c, 0x14,
                                        0x9a, 0xfb, 0xf4, 0xc8,
                                        0x99, 0x6f, 0xb9, 0x24,
                                        0x27, 0xae, 0x41, 0xe4,
                                        0x64, 0x9b, 0x93, 0x4c,
                                        0xa4, 0x95, 0x99, 0x1b,
                                        0x78, 0x52, 0xb8, 0x55};
        CHECK(calcHash(input) == expected);
    }

    {
        std::string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        std::vector<uint8_t> expected= {0x24, 0x8d, 0x6a, 0x61,
                                        0xd2, 0x06, 0x38, 0xb8,
                                        0xe5, 0xc0, 0x26, 0x93,
                                        0x0c, 0x3e, 0x60, 0x39,
                                        0xa3, 0x3c, 0xe4, 0x59,
                                        0x64, 0xff, 0x21, 0x67,
                                        0xf6, 0xec, 0xed, 0xd4,
                                        0x19, 0xdb, 0x06, 0xc1};
        CHECK(calcHash(input) == expected);
    }
}
