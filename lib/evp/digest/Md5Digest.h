#pragma once

#include "EvpDigest.h"

class Md5Digest : public EvpDigest
{
  public:
    Md5Digest() : EvpDigest()
    {
        Init(EVP_md5());
    }

    Md5Digest(const Md5Digest& ) = delete;
    Md5Digest operator=(const Md5Digest& ) = delete;
};
