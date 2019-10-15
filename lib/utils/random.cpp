#include "random.h"
#include <openssl/rand.h>
#include "SslException.h"

void sslpp::rand::getBytes(std::vector<uint8_t>& data)
{
    getBytes(data.data(), data.size());
}

std::vector<uint8_t> sslpp::rand::getBytes(size_t count)
{
    std::vector<uint8_t> buffer(count);
    getBytes(buffer);
    return buffer;
}

void sslpp::rand::getBytes(uint8_t* pData, size_t count)
{
    if (!RAND_bytes(pData, count))
        throw SslException("Failed to call RAND_bytes");
}

