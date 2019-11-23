#pragma once

#include <openssl/evp.h>

#include <vector>

class EvpDigest
{
  protected:
    explicit EvpDigest();
    void Init(const EVP_MD* type);

  public:
    EvpDigest(const EvpDigest&) = delete;
    EvpDigest& operator=(const EvpDigest&) = delete;

    void Update(const uint8_t* data, size_t dataLength);
    std::vector<uint8_t> Final();

    ~EvpDigest();

  private:
    EVP_MD_CTX *m_pCtx;
};
