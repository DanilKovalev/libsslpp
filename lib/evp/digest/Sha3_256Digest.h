#pragma once

#include "EvpDigest.h"

class Sha3_256Digest : public EvpDigest
{
  public:
    Sha3_256Digest() : EvpDigest()
    {
        Init(EVP_sha3_256());
    }

    Sha3_256Digest(const Sha3_256Digest& ) = delete;
    Sha3_256Digest operator=(const Sha3_256Digest& ) = delete;
};
