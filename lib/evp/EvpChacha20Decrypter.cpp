#include "EvpChacha20Decrypter.h"
#include <iostream>

EvpChacha20Decryption::EvpChacha20Decryption(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv)
  : EvpDecryptionCtx()
{
    const EVP_CIPHER* pCipher = EVP_chacha20();

    if (iv.size() != 16)
        throw std::runtime_error("Wrong iv length. expected 128 bits");

    if (key.size() != 32)
        throw std::runtime_error("Wrong key length. expected 256 bits");

    decryptInitEx(pCipher, nullptr, nullptr, nullptr);
    decryptInitEx(nullptr, nullptr, (uint8_t*)key.data(), nullptr);
    decryptInitEx(nullptr, nullptr, nullptr, (uint8_t*)iv.data());
}

std::vector<uint8_t> EvpChacha20Decryption::decrypt(const std::vector<uint8_t> &cipherData)
{
    return EvpChacha20Decryption::decrypt(cipherData.data(), cipherData.size());
}

std::vector<uint8_t> EvpChacha20Decryption::decrypt(const uint8_t* pData, size_t dataLength)
{
    std::vector<uint8_t> cipherData(dataLength);
    EvpDecryptionCtx::decrypt(pData, dataLength, cipherData);
    return cipherData;
}
