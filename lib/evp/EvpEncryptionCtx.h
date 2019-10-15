#pragma once
#include <openssl/evp.h>
#include "EvpCipherCtx.h"
#include "cstddef"

class EvpEncryptionCtx : protected EvpCipherCtx
{
  public:
    EvpEncryptionCtx();

    void updateAad(const std::vector<std::byte>& data);
    void updateAad(const uint8_t* aad, size_t size);
    size_t encrypt(const std::vector<std::byte>& plainData, std::vector<std::byte>& cipherData);
    size_t encrypt(const uint8_t* pData, size_t dataLength, std::vector<std::byte>& cipherData);
    size_t encrypt(uint8_t* pOut, size_t outLen, const uint8_t* pIn, size_t inLen);
};
