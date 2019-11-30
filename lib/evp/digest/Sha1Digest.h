#pragma once

#include "EvpDigest.h"

class Sha1Digest : public EvpDigest
{
  public:
    Sha1Digest() : EvpDigest()
    {
        Init(EVP_sha1());
    }

    Sha1Digest(const Sha1Digest& ) = delete;
    Sha1Digest operator=(const Sha1Digest& ) = delete;
};
