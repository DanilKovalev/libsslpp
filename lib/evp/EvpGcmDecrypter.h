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

    std::vector<std::byte> decrypt(const std::vector<std::byte>& cipherData);
    std::vector<std::byte> decrypt(const uint8_t* pData, size_t dataLength);
    void setTag(const std::vector<std::byte>& tag);
    void final();
};
