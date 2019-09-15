#pragma once

#include "utils/ObjectHelper.h"
#include "utils/ObjectHolder.h"

#include <openssl/evp.h>

#include <vector>

class EvpCipherCtx : public ObjectHolder<EVP_CIPHER_CTX, EvpCipherCtx>
{
    using RawType = EVP_CIPHER_CTX;
    friend class ObjectHelper<EvpCipherCtx>;

  private:
    EvpCipherCtx(RawType* pRaw, bool acquire) noexcept
      : ObjectHolder(pRaw, acquire)
    {
    }

  public:
    EvpCipherCtx();

    EvpCipherCtx(const EvpCipherCtx& other) = default;
    EvpCipherCtx(EvpCipherCtx&& other) = default;

    EvpCipherCtx& operator=(const EvpCipherCtx& other)
    {
        ObjectHolder::operator=(other);
        return *this;
    }

    EvpCipherCtx& operator=(EvpCipherCtx&& other) noexcept
    {
        ObjectHolder::operator=(std::move(other));
        return *this;
    }

    ~EvpCipherCtx() = default;

    static EVP_CIPHER_CTX* duplicate(EVP_CIPHER_CTX* other);
    static void destroy(EVP_CIPHER_CTX* raw) noexcept;
    inline EVP_CIPHER_CTX* raw()
    {
        return m_raw;
    }
    inline const EVP_CIPHER_CTX* raw() const
    {
        return m_raw;
    }

    void encryptInitEx(const EVP_CIPHER* cipher, ENGINE* impl, const unsigned char* key, const unsigned char* iv);
    void decryptInitEx(const EVP_CIPHER* cipher, ENGINE* impl, const unsigned char* key, const unsigned char* iv);

    void SetKey(const std::vector<uint8_t>& key);

    void encryptUpdate(unsigned char* out, int* outl, const unsigned char* in, int inl);
    void decryptUpdate(unsigned char* out, int* outl, const unsigned char* in, int inl);

    void setIv(const std::vector<uint8_t>& iv);
    int getIvLenght() const;
    const uint8_t* getIvData() const;
    std::vector<uint8_t> getIv() const;

    void encryptFinalEx(unsigned char* out, int* outl);
    void decryptFinalEx(unsigned char* out, int* outl);
    void ctrl(int type, int arg, void* ptr);

    [[nodiscard]] const EVP_CIPHER* GetCipher() const noexcept;

  private:
    static EVP_CIPHER_CTX* init();
};
