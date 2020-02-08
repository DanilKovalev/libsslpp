#pragma once

#include "EvpDecrytptionCtx.h"

class EvpChacha20Decryption : public EvpDecryptionCtx
{
  public:
    EvpChacha20Decryption(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);

    EvpChacha20Decryption(const EvpChacha20Decryption& other) = delete;
    EvpChacha20Decryption& operator=(const EvpChacha20Decryption& other) = delete;

    ~EvpChacha20Decryption() = default;

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipherData);
    std::vector<uint8_t> decrypt(const uint8_t* pData, size_t cipherData);
};


