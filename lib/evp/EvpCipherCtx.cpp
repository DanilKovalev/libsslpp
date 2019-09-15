#include "EvpCipherCtx.h"

#include "SslException.h"

#include <iostream>
#include <memory>
#include <utility>

using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

EvpCipherCtx::EvpCipherCtx()
  : ObjectHolder(init(), true)
{
}

EVP_CIPHER_CTX* EvpCipherCtx::init()
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        throw SslException("EVP_CIPHER_CTX_new");

    return ctx;
}

void EvpCipherCtx::encryptInitEx(const EVP_CIPHER* cipher,
                                 ENGINE* impl,
                                 const unsigned char* key,
                                 const unsigned char* iv)
{
    if (1 != EVP_EncryptInit_ex(m_raw, cipher, impl, key, iv))
        throw SslException("Failed to call EVP_EncryptInit_ex");
}

void EvpCipherCtx::decryptInitEx(const EVP_CIPHER* cipher,
                                 ENGINE* impl,
                                 const unsigned char* key,
                                 const unsigned char* iv)
{
    if (1 != EVP_DecryptInit_ex(m_raw, cipher, impl, key, iv))
        throw SslException("Failed to call EVP_DecryptInit_ex");
}

void EvpCipherCtx::SetKey(const std::vector<uint8_t>& key)
{
    int res = 1;
    if (EVP_CIPHER_CTX_encrypting(m_raw))
        res = EVP_EncryptInit_ex(m_raw, nullptr, nullptr, key.data(), nullptr);
    else
        res = EVP_DecryptInit_ex(m_raw, nullptr, nullptr, key.data(), nullptr);

    if (res != 1)
        throw SslException("Failed to set key into evp context");
}

void EvpCipherCtx::setIv(const std::vector<uint8_t>& iv)
{
    int res = 1;
    if (EVP_CIPHER_CTX_encrypting(m_raw))
        res = EVP_EncryptInit_ex(m_raw, NULL, NULL, nullptr, iv.data());
    else
        res = EVP_DecryptInit_ex(m_raw, nullptr, nullptr, nullptr, iv.data());

    if (res != 1)
        throw SslException("Failed to set iv into evp context");
}

EVP_CIPHER_CTX* EvpCipherCtx::duplicate(EVP_CIPHER_CTX* other)
{
    EVP_CIPHER_CTX_ptr out(init(), EVP_CIPHER_CTX_free);
    if (EVP_CIPHER_CTX_copy(out.get(), other) != 1)
        throw SslException("EVP_CIPHER_CTX_new");

    return out.release();
}

void EvpCipherCtx::destroy(EVP_CIPHER_CTX* raw) noexcept
{
    EVP_CIPHER_CTX_free(raw);
}

const EVP_CIPHER* EvpCipherCtx::GetCipher() const noexcept
{
    return EVP_CIPHER_CTX_cipher(m_raw);
}

void EvpCipherCtx::encryptUpdate(unsigned char* out, int* outl, const unsigned char* in, int inl)
{
    if (1 != EVP_EncryptUpdate(m_raw, out, outl, in, inl))
        throw SslException("Failed to call EVP_EncryptUpdate");
}

void EvpCipherCtx::decryptUpdate(unsigned char* out, int* outl, const unsigned char* in, int inl)
{

    if (1 != EVP_DecryptUpdate(m_raw, out, outl, in, inl))
        throw SslException("Failed to call EVP_DecryptUpdate");
}

void EvpCipherCtx::encryptFinalEx(unsigned char* out, int* outl)
{
    if (1 != EVP_EncryptFinal_ex(m_raw, out, outl))
        throw SslException("Failed to call EVP_EncryptFinal_ex");
}

void EvpCipherCtx::decryptFinalEx(unsigned char* out, int* outl)
{
    if (1 != EVP_DecryptFinal_ex(m_raw, out, outl))
        throw SslException("Failed to call EVP_DecryptFinal_ex");
}

int EvpCipherCtx::getIvLenght() const
{
    return EVP_CIPHER_CTX_iv_length(m_raw);
}

const uint8_t* EvpCipherCtx::getIvData() const
{
    return EVP_CIPHER_CTX_iv(m_raw);
}

std::vector<uint8_t> EvpCipherCtx::getIv() const
{
    return std::vector<uint8_t>(getIvData(), getIvData() + getIvLenght());
}

void EvpCipherCtx::ctrl(int type, int arg, void* ptr)
{
    if (!EVP_CIPHER_CTX_ctrl(m_raw, type, arg, ptr))
        throw SslException("Failed to call EVP_CIPHER_CTX_ctrl");
}
