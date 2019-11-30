#pragma once

#include "EvpDigest.h"

class Sha512Digest : public EvpDigest
{
  public:
    Sha512Digest() : EvpDigest()
    {
        Init(EVP_sha512());
    }

    Sha512Digest(const Sha512Digest& ) = delete;
    Sha512Digest operator=(const Sha512Digest& ) = delete;
};
