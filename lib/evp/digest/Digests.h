#pragma once

#include "EvpDigest.h"

class Sha1Digest : public EvpDigest
{
  public:
    Sha1Digest() : EvpDigest(EVP_sha1()){};
};

class Md5Digest : public EvpDigest
{
  public:
    Md5Digest() : EvpDigest(EVP_md5()) {};
};

class Sha3_256Digest : public EvpDigest
{
  public:
    Sha3_256Digest() : EvpDigest(EVP_sha3_256()){};
};

class Sha3_512Digest : public EvpDigest
{
  public:
    Sha3_512Digest() : EvpDigest(EVP_sha3_512()){};
};

class Sha256Digest : public EvpDigest
{
  public:
    Sha256Digest() : EvpDigest(EVP_sha256()){};
};

class Sha512Digest : public EvpDigest
{
  public:
    Sha512Digest() : EvpDigest(EVP_sha512()){};
};