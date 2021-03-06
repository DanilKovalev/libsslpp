#include "EvpEncryptionCtx.h"

EvpEncryptionCtx::EvpEncryptionCtx()
  : EvpCipherCtx()
{
}

void EvpEncryptionCtx::updateAad(const std::vector<uint8_t>& data)
{
    updateAad((uint8_t*)data.data(), data.size());
}

void EvpEncryptionCtx::updateAad(const uint8_t* aad, size_t size)
{
    int len;
    encryptUpdate(nullptr, &len, aad, size);
}

size_t EvpEncryptionCtx::encrypt(const std::vector<uint8_t>& plainData, std::vector<uint8_t>& cipherData)
{
    return encrypt(plainData.data(), plainData.size(), cipherData);
}

size_t EvpEncryptionCtx::encrypt(const uint8_t* pData, size_t dataLength, std::vector<uint8_t>& cipherData)
{
    return encrypt((uint8_t*)cipherData.data(), cipherData.size(), pData, dataLength);
}

size_t EvpEncryptionCtx::encrypt(uint8_t* pOut, size_t outLen, const uint8_t* pIn, size_t inLen)
{
    int len = outLen;
    EvpCipherCtx::encryptUpdate(pOut, &len, pIn, inLen);
    return len;

}
