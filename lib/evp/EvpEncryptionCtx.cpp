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
    int len = cipherData.size();
    encryptUpdate((uint8_t*)cipherData.data(), &len, (uint8_t*)plainData.data(), plainData.size());
    return len;
}

