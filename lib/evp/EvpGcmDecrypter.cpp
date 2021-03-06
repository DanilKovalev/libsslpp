#include "EvpGcmDecrypter.h"

#include "utils/StrFormat.h"

EvpGcmDecrypter::EvpGcmDecrypter(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv)
  : EvpDecryptionCtx()
{
    const EVP_CIPHER* pCipher = nullptr;
    if (key.size() == 16)
        pCipher = EVP_aes_128_gcm();
    else if (key.size() == 24)
        pCipher = EVP_aes_192_gcm();
    else if (key.size() == 32)
        pCipher = EVP_aes_256_gcm();
    else
        throw std::logic_error(utils::strFormat("Unsupported key length %1%", key.size()));

    decryptInitEx(pCipher, nullptr, nullptr, nullptr);
    decryptInitEx(nullptr, nullptr, (uint8_t*)key.data(), nullptr);
    ctrl(EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    decryptInitEx(nullptr, nullptr, nullptr, (uint8_t*)iv.data());
}


std::vector<uint8_t> EvpGcmDecrypter::decrypt(const std::vector<uint8_t>& cipherData)
{
    return decrypt((uint8_t*)cipherData.data(), cipherData.size());
}

std::vector<uint8_t> EvpGcmDecrypter::decrypt(const uint8_t* pData, size_t dataLength)
{
    std::vector<uint8_t> plainData(dataLength);
    EvpDecryptionCtx::decrypt(pData, dataLength, plainData);
    return plainData;
}

void EvpGcmDecrypter::setTag(const std::vector<uint8_t>& tag)
{
    if (tag.size() != 16)
        throw std::logic_error(utils::strFormat("Wrong tag size %1% != 16", tag.size()));
    EvpCipherCtx::ctrl(EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data());
}

void EvpGcmDecrypter::setTag(const uint8_t* tag)
{
    EvpCipherCtx::ctrl(EVP_CTRL_GCM_SET_TAG, getTagLength(), (void*)tag);
}

size_t EvpGcmDecrypter::getTagLength() const
{
    return 16;
}

void EvpGcmDecrypter::final()
{
    int len;
    EvpCipherCtx::decryptFinalEx(nullptr, &len);
}
