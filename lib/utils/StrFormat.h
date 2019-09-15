#pragma once
#include <boost/format.hpp>
#include <boost/utility/string_ref.hpp>

namespace utils
{
template <typename ... Args>
static inline std::string strFormat(const std::string& fmt , const Args&& ... args)
{
    return boost::str((boost::format( fmt) % ... % args));
}

template <typename ... Args>
static inline std::string strFormat(const char* fmt , const Args&& ... args)
{
    return boost::str((boost::format(fmt) % ... % args));
}

}
