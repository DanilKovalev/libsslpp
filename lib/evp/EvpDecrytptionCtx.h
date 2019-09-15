#pragma once
#include <openssl/evp.h>
#include "EvpCipherCtx.h"
#include "cstddef"

class EvpDecryptionCtx : protected EvpCipherCtx
{
  public:
    EvpDecryptionCtx();

    void updateAad(const std::vector<std::byte>& data);
    void updateAad(const uint8_t* aad, size_t size);
    size_t decrypt(const std::vector<std::byte>& cipherData, std::vector<std::byte>& plainData);
};
