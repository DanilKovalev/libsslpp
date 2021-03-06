#pragma once
#include "EvpDecrytptionCtx.h"

class EvpGcmDecrypter : public EvpDecryptionCtx
{
  public:
    EvpGcmDecrypter(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);

    EvpGcmDecrypter(const EvpGcmDecrypter& other) = delete;
  //  EvpGcmDecrypter(EvpGcmDecrypter&& other) noexcept;

    EvpGcmDecrypter& operator=(const EvpGcmDecrypter& other) = delete;
//    EvpGcmDecrypter& operator=(EvpGcmDecrypter&& other) noexcept;

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipherData);
    std::vector<uint8_t> decrypt(const uint8_t* pData, size_t dataLength);
    void setTag(const std::vector<uint8_t>& tag);
    void setTag(const uint8_t* tag);
    size_t getTagLength() const;
    void final();
};
