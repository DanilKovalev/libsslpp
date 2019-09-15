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
};