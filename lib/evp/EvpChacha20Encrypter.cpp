#include "EvpChacha20Encrypter.h"
#include <iostream>

EvpChacha20Encrypter::EvpChacha20Encrypter(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv)
        : EvpEncryptionCtx()
{
    const EVP_CIPHER* pCipher = EVP_chacha20();

    if (iv.size() != 16)
        throw std::runtime_error("Wrong iv length. expected 128 bits");

    if (key.size() != 32)
        throw std::runtime_error("Wrong key length. expected 256 bits");

    encryptInitEx(pCipher, nullptr, nullptr, nullptr);
    encryptInitEx(nullptr, nullptr, (uint8_t*)key.data(), nullptr);
    encryptInitEx(nullptr, nullptr, nullptr, (uint8_t*)iv.data());
}

std::vector<uint8_t> EvpChacha20Encrypter::encrypt(const std::vector<uint8_t> &plainData)
{
    std::vector<uint8_t> cipherData(plainData.size());
    EvpEncryptionCtx::encrypt(plainData, cipherData);
    return cipherData;
}

std::vector<uint8_t> EvpChacha20Encrypter::encrypt(const uint8_t* pData, size_t dataLength)
{
    std::vector<uint8_t> cipherData(dataLength);
    EvpEncryptionCtx::encrypt(pData, dataLength, cipherData);
    return cipherData;
}
