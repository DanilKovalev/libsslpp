#include "EvpDecrytptionCtx.h"

EvpDecryptionCtx::EvpDecryptionCtx()
  : EvpCipherCtx()
{
}

void EvpDecryptionCtx::updateAad(const std::vector<std::byte>& data)
{
    updateAad((uint8_t*)data.data(), data.size());
}

void EvpDecryptionCtx::updateAad(const uint8_t* aad, size_t size)
{
    int len;
    decryptUpdate(nullptr, &len, aad, size);
}

size_t EvpDecryptionCtx::decrypt(const std::vector<std::byte>& cipherData, std::vector<std::byte>& plainData)
{
    return decrypt((const uint8_t*)cipherData.data(), cipherData.size(), plainData);
}

size_t EvpDecryptionCtx::decrypt(const uint8_t* pData, size_t dataLength, std::vector<std::byte>& plainData)
{
    return decrypt((uint8_t*)plainData.data(), plainData.size(), pData, dataLength);
}

size_t EvpDecryptionCtx::decrypt(uint8_t* pOut, size_t outLen, const uint8_t* pIn, size_t inLen)
{
    int len = outLen;
    decryptUpdate(pOut, &len, pIn, inLen);
    return len;
}

