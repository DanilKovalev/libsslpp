#include "evp/digest/Sha3_512Digest.h"
#include <string>
#include <catch2/catch.hpp>

//https://www.di-mgt.com.au/sha_testvectors.html#testvectors

static std::vector<uint8_t> calcHash(const std::string& input)
{
    return EvpDigest::CalcHash<Sha3_512Digest>((const uint8_t*)input.c_str(), input.size());
}

TEST_CASE("Sha3_512", "[digest][evp]")
{
    {
        std::vector<uint8_t> expected= {0xb7, 0x51, 0x85, 0x0b,
                                        0x1a, 0x57, 0x16, 0x8a,
                                        0x56, 0x93, 0xcd, 0x92,
                                        0x4b, 0x6b, 0x09, 0x6e,
                                        0x08, 0xf6, 0x21, 0x82,
                                        0x74, 0x44, 0xf7, 0x0d,
                                        0x88, 0x4f, 0x5d, 0x02,
                                        0x40, 0xd2, 0x71, 0x2e,
                                        0x10, 0xe1, 0x16, 0xe9,
                                        0x19, 0x2a, 0xf3, 0xc9,
                                        0x1a, 0x7e, 0xc5, 0x76,
                                        0x47, 0xe3, 0x93, 0x40,
                                        0x57, 0x34, 0x0b, 0x4c,
                                        0xf4, 0x08, 0xd5, 0xa5,
                                        0x65, 0x92, 0xf8, 0x27,
                                        0x4e, 0xec, 0x53, 0xf0};
        std::string input = "abc";
        CHECK(calcHash(input) == expected);
    }

    {
        std::string input = "";
        std::vector<uint8_t> expected= {0xa6, 0x9f, 0x73, 0xcc,
                                        0xa2, 0x3a, 0x9a, 0xc5,
                                        0xc8, 0xb5, 0x67, 0xdc,
                                        0x18, 0x5a, 0x75, 0x6e,
                                        0x97, 0xc9, 0x82, 0x16,
                                        0x4f, 0xe2, 0x58, 0x59,
                                        0xe0, 0xd1, 0xdc, 0xc1,
                                        0x47, 0x5c, 0x80, 0xa6,
                                        0x15, 0xb2, 0x12, 0x3a,
                                        0xf1, 0xf5, 0xf9, 0x4c,
                                        0x11, 0xe3, 0xe9, 0x40,
                                        0x2c, 0x3a, 0xc5, 0x58,
                                        0xf5, 0x00, 0x19, 0x9d,
                                        0x95, 0xb6, 0xd3, 0xe3,
                                        0x01, 0x75, 0x85, 0x86,
                                        0x28, 0x1d, 0xcd, 0x26};
        CHECK(calcHash(input) == expected);
    }

    {
        std::string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        std::vector<uint8_t> expected= {0x04, 0xa3, 0x71, 0xe8,
                                        0x4e, 0xcf, 0xb5, 0xb8,
                                        0xb7, 0x7c, 0xb4, 0x86,
                                        0x10, 0xfc, 0xa8, 0x18,
                                        0x2d, 0xd4, 0x57, 0xce,
                                        0x6f, 0x32, 0x6a, 0x0f,
                                        0xd3, 0xd7, 0xec, 0x2f,
                                        0x1e, 0x91, 0x63, 0x6d,
                                        0xee, 0x69, 0x1f, 0xbe,
                                        0x0c, 0x98, 0x53, 0x02,
                                        0xba, 0x1b, 0x0d, 0x8d,
                                        0xc7, 0x8c, 0x08, 0x63,
                                        0x46, 0xb5, 0x33, 0xb4,
                                        0x9c, 0x03, 0x0d, 0x99,
                                        0xa2, 0x7d, 0xaf, 0x11,
                                        0x39, 0xd6, 0xe7, 0x5e};
        CHECK(calcHash(input) == expected);
    }
}