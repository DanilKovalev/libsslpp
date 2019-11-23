#include "EvpDigest.h"
#include "SslException.h"

EvpDigest::EvpDigest()
 : m_pCtx(EVP_MD_CTX_create())
{
    if (m_pCtx == nullptr)
        throw SslException("Failed to create evp md context.");
}

void EvpDigest::Init(const EVP_MD* type)
{
    if (EVP_DigestInit(m_pCtx, type) != 1)
        throw SslException("Failed to init evp digest.");
}

void EvpDigest::Update(const uint8_t* data, size_t dataLength)
{
    if (EVP_DigestUpdate(m_pCtx, (void*) data, dataLength) != 1)
        throw SslException("Failed to update digest.");
}

std::vector<uint8_t> EvpDigest::Final()
{
    std::vector<uint8_t> result(GetHashSize());

    unsigned int resSize;
    if (EVP_DigestFinal(m_pCtx, result.data(), &resSize) != 1)
        throw SslException("Failed to call digest final.");

    return result;
}

EvpDigest::~EvpDigest()
{
    EVP_MD_CTX_destroy(m_pCtx);
}

size_t EvpDigest::GetHashSize() const
{
    return EVP_MD_size(EVP_MD_CTX_md(m_pCtx));
}
