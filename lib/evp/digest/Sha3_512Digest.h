#pragma once

#include "EvpDigest.h"

class Sha3_512Digest : public EvpDigest
{
  public:
    Sha3_512Digest() : EvpDigest()
    {
        Init(EVP_sha3_512());
    }

    Sha3_512Digest(const Sha3_512Digest& ) = delete;
    Sha3_512Digest operator=(const Sha3_512Digest& ) = delete;
};
