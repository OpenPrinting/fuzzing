#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

static std::string HexByte(uint8_t value) {
  std::ostringstream stream;
  stream << std::hex << std::setfill('0') << std::setw(2)
         << static_cast<unsigned>(value);
  return stream.str();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  const char *event_path = std::getenv("SMT_FUZZER_EVENT_OUT");
  if (event_path != nullptr && data[0] != 0x41) {
    std::ofstream event(event_path);
    event << "{\n"
          << "  \"target_id\": \"branch_event_template\",\n"
          << "  \"input_path\": \"REPLACE_WITH_INPUT_PATH\",\n"
          << "  \"input_sha256\": \"REPLACE_WITH_INPUT_SHA256\",\n"
          << "  \"offset\": 0,\n"
          << "  \"width\": 1,\n"
          << "  \"endianness\": \"little\",\n"
          << "  \"signed\": false,\n"
          << "  \"op\": \"eq\",\n"
          << "  \"rhs\": 65,\n"
          << "  \"description\": \"first byte must equal ASCII A; observed 0x"
          << HexByte(data[0]) << "\"\n"
          << "}\n";
  }

  if (data[0] == 0x41) {
    std::fprintf(stderr, "template branch reached\n");
  }
  return 0;
}
