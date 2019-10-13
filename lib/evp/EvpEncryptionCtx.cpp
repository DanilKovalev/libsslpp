#include "EvpEncryptionCtx.h"

EvpEncryptionCtx::EvpEncryptionCtx()
  : EvpCipherCtx()
{
}

void EvpEncryptionCtx::updateAad(const std::vector<std::byte>& data)
{
    updateAad((uint8_t*)data.data(), data.size());
}

void EvpEncryptionCtx::updateAad(const uint8_t* aad, size_t size)
{
    int len;
    encryptUpdate(nullptr, &len, aad, size);
}

size_t EvpEncryptionCtx::encrypt(const std::vector<std::byte>& plainData, std::vector<std::byte>& cipherData)
{
    return encrypt((const uint8_t*)plainData.data(), plainData.size(), cipherData);
}

size_t EvpEncryptionCtx::encrypt(const uint8_t* pData, size_t dataLength, std::vector<std::byte>& cipherData)
{
    int len = cipherData.size();
    EvpCipherCtx::encryptUpdate((uint8_t*)cipherData.data(), &len, pData, dataLength);
    return len;
}


