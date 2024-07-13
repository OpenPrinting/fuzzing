// Provide input for C based harnesses

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {

    // For fuzz_array

    struct FuzzArray {
        char* str1;
        char* str2;
    };

    void generate_fuzz_array_data(const uint8_t *data, size_t size, FuzzArray *outData) {

    FuzzedDataProvider fuzz_data(data, size);
    std::string fuzz_str1 = fuzz_data.ConsumeRandomLengthString(1);
    std::string fuzz_str2 = fuzz_data.ConsumeRandomLengthString(1);
    // int num = fuzz_data.ConsumeIntegral<int>();

    outData->str1 = new char[fuzz_str1.length() + 1];
    std::strcpy(outData->str1, fuzz_str1.c_str());

    outData->str2 = new char[fuzz_str2.length() + 1];
    std::strcpy(outData->str2, fuzz_str2.c_str());
    // outData->num = num;
    }

    void free_fuzz_array_data(FuzzArray *data) {
        delete[] data->str1;
        delete[] data->str2;
    }

}