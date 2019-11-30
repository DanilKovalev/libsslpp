#include "evp/digest/Sha1Digest.h"
#include <string>
#include <catch2/catch.hpp>

//https://www.di-mgt.com.au/sha_testvectors.html#testvectors

static std::vector<uint8_t> calcHash(const std::string& input)
{
    return EvpDigest::CalcHash<Sha1Digest>((const uint8_t*)input.c_str(), input.size());
}

TEST_CASE("Sha1", "[digest][evp]")
{
    {
        std::string input = "abc";
        std::vector<uint8_t> expected= {0xa9, 0x99, 0x3e, 0x36,
                                        0x47, 0x06, 0x81, 0x6a,
                                        0xba, 0x3e, 0x25, 0x71,
                                        0x78, 0x50, 0xc2, 0x6c,
                                        0x9c, 0xd0, 0xd8, 0x9d};

        CHECK(calcHash(input) == expected);
    }

    {
        std::string input = "";
        std::vector<uint8_t> expected= {0xda, 0x39, 0xa3, 0xee,
                                        0x5e, 0x6b, 0x4b, 0x0d,
                                        0x32, 0x55, 0xbf, 0xef,
                                        0x95, 0x60, 0x18, 0x90,
                                        0xaf, 0xd8, 0x07, 0x09};
        CHECK(calcHash(input) == expected);
    }

    {
        std::string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        std::vector<uint8_t> expected= {0x84, 0x98, 0x3e, 0x44,
                                        0x1c, 0x3b, 0xd2, 0x6e,
                                        0xba, 0xae, 0x4a, 0xa1,
                                        0xf9, 0x51, 0x29, 0xe5,
                                        0xe5, 0x46, 0x70, 0xf1};
        CHECK(calcHash(input) == expected);
    }
}
