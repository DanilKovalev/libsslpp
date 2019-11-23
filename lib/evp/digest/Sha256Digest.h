#pragma once

#include "EvpDigest.h"

class Sha256Digest : public EvpDigest
{
  public:
    Sha256Digest() : EvpDigest()
    {
        Init(EVP_sha256());
    }

    Sha256Digest(const Sha256Digest& ) = delete;
    Sha256Digest operator=(const Sha256Digest& ) = delete;
};
