#include "evp/digest/Sha3_256Digest.h"
#include <string>
#include <catch2/catch.hpp>

//https://www.di-mgt.com.au/sha_testvectors.html#testvectors

static std::vector<uint8_t> calcHash(const std::string& input)
{
    return EvpDigest::CalcHash<Sha3_256Digest>((const uint8_t*)input.c_str(), input.size());
}

TEST_CASE("Sha3_256", "[digest][evp]")
{
    {
        std::string input = "abc";
        std::vector<uint8_t> expected= {0x3a, 0x98, 0x5d, 0xa7,
                                        0x4f, 0xe2, 0x25, 0xb2,
                                        0x04, 0x5c, 0x17, 0x2d,
                                        0x6b, 0xd3, 0x90, 0xbd,
                                        0x85, 0x5f, 0x08, 0x6e,
                                        0x3e, 0x9d, 0x52, 0x5b,
                                        0x46, 0xbf, 0xe2, 0x45,
                                        0x11, 0x43, 0x15, 0x32};
        CHECK(calcHash(input) == expected);
    }

    {
        std::string input = "";
        std::vector<uint8_t> expected= {0xa7, 0xff, 0xc6, 0xf8,
                                        0xbf, 0x1e, 0xd7, 0x66,
                                        0x51, 0xc1, 0x47, 0x56,
                                        0xa0, 0x61, 0xd6, 0x62,
                                        0xf5, 0x80, 0xff, 0x4d,
                                        0xe4, 0x3b, 0x49, 0xfa,
                                        0x82, 0xd8, 0x0a, 0x4b,
                                        0x80, 0xf8, 0x43, 0x4a};
        CHECK(calcHash(input) == expected);
    }

    {
        std::string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        std::vector<uint8_t> expected= {0x41, 0xc0, 0xdb, 0xa2,
                                        0xa9, 0xd6, 0x24, 0x08,
                                        0x49, 0x10, 0x03, 0x76,
                                        0xa8, 0x23, 0x5e, 0x2c,
                                        0x82, 0xe1, 0xb9, 0x99,
                                        0x8a, 0x99, 0x9e, 0x21,
                                        0xdb, 0x32, 0xdd, 0x97,
                                        0x49, 0x6d, 0x33, 0x76};
        CHECK(calcHash(input) == expected);
    }
}