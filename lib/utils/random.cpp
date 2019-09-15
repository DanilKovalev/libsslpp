#include "random.h"
#include <openssl/rand.h>
#include "SslException.h"

void getBytes(std::vector<uint8_t>& data)
{
    if (!RAND_bytes(data.data(), data.size()))
        throw SslException("Failed to call RAND_bytes");
}

