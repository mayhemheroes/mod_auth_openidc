#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int oidc_strnenvcmp(const char *a, const char *b, int len);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str1 = provider.ConsumeRandomLengthString(1000);
    std::string str2 = provider.ConsumeRandomLengthString(1000);
    oidc_strnenvcmp(str1.c_str(), str2.c_str(), -1);
    return 0;
}