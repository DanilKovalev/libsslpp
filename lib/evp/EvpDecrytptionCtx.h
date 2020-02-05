#pragma once
#include <openssl/evp.h>
#include "EvpCipherCtx.h"
#include "cstddef"

class EvpDecryptionCtx : protected EvpCipherCtx
{
  public:
    EvpDecryptionCtx();

    void updateAad(const std::vector<uint8_t>& data);
    void updateAad(const uint8_t* aad, size_t size);
    size_t decrypt(const std::vector<uint8_t>& cipherData, std::vector<uint8_t>& plainData);
    size_t decrypt(const uint8_t* pData, size_t dataLength, std::vector<uint8_t>& plainData);
    size_t decrypt(uint8_t* pOut, size_t outLen, const uint8_t* pIn, size_t inLen);
};
