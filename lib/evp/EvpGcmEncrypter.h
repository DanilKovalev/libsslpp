#pragma once

#include "EvpEncryptionCtx.h"

class EvpGcmEncrypter : public EvpEncryptionCtx
{
  public:
    EvpGcmEncrypter(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);

    EvpGcmEncrypter(const EvpGcmEncrypter& other) = delete;
//    EvpGcmEncrypter(EvpGcmEncrypter&& other) noexcept;

    EvpGcmEncrypter& operator=(const EvpGcmEncrypter& other) = delete;
//    EvpGcmEncrypter& operator= (EvpGcmEncrypter&& other) noexcept;

    ~EvpGcmEncrypter() = default;

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plainData);
    std::vector<uint8_t> encrypt(const uint8_t* pData, size_t dataLength);
    void final();
    std::vector<uint8_t> getTag();
    void getTag(uint8_t* tag);
    size_t getTagLength() const;
};
