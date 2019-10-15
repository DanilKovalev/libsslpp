#pragma once

#include <vector>
#include <cstdint>

namespace sslpp::rand
{
    void getBytes(std::vector<uint8_t>& data);
    std::vector<uint8_t> getBytes(size_t count);
    void getBytes(uint8_t* pData, size_t count);

}

