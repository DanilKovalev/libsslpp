#include "EvpDigest.h"

#include "SslException.h"

#include <memory>

using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EvpDigest::destroy)>;

EvpDigest::EvpDigest(const EVP_MD* type)
  : ObjectHolder(create(), true)
{
    if (EVP_DigestInit(m_raw, type) != 1)
        throw SslException("Failed to init evp digest.");
}

EvpDigest::EvpDigest(const EvpDigest& other)
  : ObjectHolder(duplicate(other.m_raw), true)
{
}

void EvpDigest::Update(const uint8_t* data, size_t dataLength)
{
    if (EVP_DigestUpdate(m_raw, (void*)data, dataLength) != 1)
        throw SslException("Failed to update digest.");
}

std::vector<uint8_t> EvpDigest::Final()
{
    std::vector<uint8_t> result(GetHashSize());

    unsigned int resSize;
    if (EVP_DigestFinal(m_raw, result.data(), &resSize) != 1)
        throw SslException("Failed to call digest final.");

    return result;
}

void EvpDigest::Reset()
{
    if (EVP_MD_CTX_reset(m_raw) != 1)
        throw SslException("Failed to reset digest contxts.");
}

size_t EvpDigest::GetHashSize() const
{
    return EVP_MD_size(EVP_MD_CTX_md(m_raw));
}

EvpDigest::RawType* EvpDigest::duplicate(RawType* other)
{
    EVP_MD_CTX_ptr newCtx(create(), EvpDigest::destroy);
    if (EVP_MD_CTX_copy(newCtx.get(), other) != 1)
        throw SslException("Failed to call EVP_MD_CTX_copy");

    return newCtx.release();
}

void EvpDigest::destroy(RawType* raw) noexcept
{
    EVP_MD_CTX_destroy(raw);
}

EvpDigest::RawType* EvpDigest::create()
{
    RawType* raw = EVP_MD_CTX_create();
    if (raw == nullptr)
        throw SslException("Failed to call EVP_MD_CTX_create");

    return raw;
}
