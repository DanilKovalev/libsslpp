#include "EvpGcmEncrypter.h"

#include "openssl/rand.h"
#include "utils/StrFormat.h"
#include "utils/random.h"

EvpGcmEncrypter::EvpGcmEncrypter(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv)
  : EvpEncryptionCtx()
{
    const EVP_CIPHER* pCipher = nullptr;
    if (key.size() == 16)
        pCipher = EVP_aes_128_gcm();
    else if (key.size() == 24)
        pCipher = EVP_aes_192_gcm();
    else if (key.size() == 32)
        pCipher = EVP_aes_256_gcm();
    else
        throw std::runtime_error(utils::strFormat("Unsupported key length %1%", key.size()));

    encryptInitEx(pCipher, nullptr, nullptr, nullptr);
    encryptInitEx(nullptr, nullptr, (uint8_t*)key.data(), nullptr);
    ctrl(EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    encryptInitEx(nullptr, nullptr, nullptr, (uint8_t*)iv.data());
}

std::vector<uint8_t> EvpGcmEncrypter::encrypt(const std::vector<uint8_t>& plainData)
{
    std::vector<uint8_t> cipherData(plainData.size());
    EvpEncryptionCtx::encrypt(plainData, cipherData);
    return cipherData;
}

std::vector<uint8_t> EvpGcmEncrypter::encrypt(const uint8_t* pData, size_t dataLength)
{
    std::vector<uint8_t> cipherData(dataLength);
    EvpEncryptionCtx::encrypt(pData, dataLength, cipherData);
    return cipherData;
}

void EvpGcmEncrypter::final()
{
    int len;
    encryptFinalEx(nullptr, &len);
}

std::vector<uint8_t> EvpGcmEncrypter::getTag()
{
    std::vector<uint8_t> tag(getTagLength(), uint8_t(0));
    ctrl(EVP_CTRL_GCM_GET_TAG, tag.size(), (uint8_t*)tag.data());
    return tag;
}

void EvpGcmEncrypter::getTag(uint8_t* tag)
{
    ctrl(EVP_CTRL_GCM_GET_TAG, getTagLength(), tag);
}

size_t EvpGcmEncrypter::getTagLength() const
{
    return 16;
}

