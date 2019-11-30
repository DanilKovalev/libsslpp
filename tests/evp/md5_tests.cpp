#include "evp/digest/Md5Digest.h"
#include <string>
#include <catch2/catch.hpp>

static std::vector<uint8_t> calcHash(const std::string& input)
{
    return EvpDigest::CalcHash<Md5Digest>((const uint8_t*)input.c_str(), input.size());
}

TEST_CASE("Md5", "[digest][evp]")
{
    {
        std::string input = "abc";
        std::vector<uint8_t> expected= {0x90, 0x01, 0x50, 0x98,
                                        0x3c, 0xd2, 0x4f, 0xb0,
                                        0xd6, 0x96, 0x3f, 0x7d,
                                        0x28, 0xe1, 0x7f, 0x72};

        CHECK(calcHash(input) == expected);
    }

    {
        std::string input = "";
        std::vector<uint8_t> expected= {0xd4, 0x1d, 0x8c, 0xd9,
                                        0x8f, 0x00, 0xb2, 0x04,
                                        0xe9, 0x80, 0x09, 0x98,
                                        0xec, 0xf8, 0x42, 0x7e};
        CHECK(calcHash(input) == expected);
    }

    {
        std::string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        std::vector<uint8_t> expected= {0x82, 0x15, 0xef, 0x07,
                                        0x96, 0xa2, 0x0b, 0xca,
                                        0xaa, 0xe1, 0x16, 0xd3,
                                        0x87, 0x6c, 0x66, 0x4a};
        CHECK(calcHash(input) == expected);
    }
}
