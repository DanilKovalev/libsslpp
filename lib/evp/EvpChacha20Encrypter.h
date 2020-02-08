#pragma once

#include "EvpEncryptionCtx.h"

class EvpChacha20Encrypter : public EvpEncryptionCtx
{
public:
    EvpChacha20Encrypter(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);

    EvpChacha20Encrypter(const EvpChacha20Encrypter& other) = delete;
    EvpChacha20Encrypter& operator=(const EvpChacha20Encrypter& other) = delete;

    ~EvpChacha20Encrypter() = default;

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plainData);
    std::vector<uint8_t> encrypt(const uint8_t* pData, size_t dataLength);
};


