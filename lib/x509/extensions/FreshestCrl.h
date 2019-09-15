#pragma once

#include "DistPoint.h"
#include "X509Extension.h"
#include "utils/StackOf.h"

#include <openssl/x509v3.h>

#include <string>

class FreshestCrl : public X509Extension
{
  public:
    static const int NID = NID_freshest_crl;

    explicit FreshestCrl(const X509Extension& ext);
    explicit FreshestCrl(X509Extension&& ext);

    FreshestCrl(const FreshestCrl&) = default;
    FreshestCrl(FreshestCrl&&) = default;

    ~FreshestCrl() = default;

    StackOf<DistPoint> getDistPoints();
};
