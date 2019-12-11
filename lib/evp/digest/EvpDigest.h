#pragma once

#include <openssl/evp.h>

#include <vector>
#include "utils/ObjectHolder.h"
#include "utils/ObjectHelper.h"

class EvpDigest : public ObjectHolder<EVP_MD_CTX, EvpDigest>
{
    using RawType = EVP_MD_CTX;
    friend class ObjectHelper<EvpDigest>;

  public:
    explicit EvpDigest(const EVP_MD* type);

    EvpDigest(const EvpDigest&) = delete;
    EvpDigest& operator=(const EvpDigest&) = delete;

    void Update(const uint8_t* data, size_t dataLength);
    std::vector<uint8_t> Final();
    void Reset();
    size_t GetHashSize() const;

    static RawType* duplicate(RawType* other);
    static void destroy(RawType* raw) noexcept;

    template <typename Hash>
    static std::vector<uint8_t> CalcHash(const uint8_t* data, size_t dataLength)
    {
        Hash hash;
        hash.Update(data, dataLength);
        return hash.Final();
    }

    virtual ~EvpDigest() = default;

  private:
    static RawType* create();
};

