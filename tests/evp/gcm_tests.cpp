#include "evp/EvpGcmDecrypter.h"
#include "evp/EvpGcmEncrypter.h"

#include <string>

#include <catch2/catch.hpp>

TEST_CASE("GCM test", "[gcm]")
{
    unsigned char* key = (unsigned char*)"01234567890123456789012345678901";
    std::vector<uint8_t> vecKey(key, key + 32);

    /* A 128 bit IV */
    unsigned char* iv = (unsigned char*)"0123456789012345";
    std::vector<uint8_t> vecIV(iv, iv + 12);

    /* Message to be encrypted */
    std::string plaintext = "The quick brown fox jumps over the lazy dog";
    std::vector<std::byte> vecPlainText;
    std::transform(
      plaintext.cbegin(), plaintext.cend(), std::back_inserter(vecPlainText), [](char c) { return std::byte(c); });

    /* Additional data */
    std::string aad = "The five boxing wizards jump quickly.";
    std::vector<std::byte> vecAad;
    std::transform(aad.cbegin(), aad.cend(), std::back_inserter(vecAad), [](char c) { return std::byte(c); });

    EvpGcmEncrypter enc(vecKey, vecIV);
    enc.updateAad(vecAad);
    auto cipher = enc.encrypt(vecPlainText);

    enc.final();
    auto tag = enc.getTag();

    SECTION("Valid check")
    {
        EvpGcmDecrypter dec(vecKey, vecIV);
        dec.updateAad(vecAad);
        dec.decrypt(cipher);
        dec.setTag(tag);
        REQUIRE_NOTHROW(dec.final());
    }

    SECTION("Forged check")
    {
        std::for_each(tag.begin(), tag.end(), [](std::byte& val) { val = std::byte(0); });
        EvpGcmDecrypter dec(vecKey, vecIV);
        dec.updateAad(vecAad);
        dec.decrypt(cipher);
        dec.setTag(tag);
        REQUIRE_THROWS(dec.final());
    }
}
