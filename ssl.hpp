////////////////////////////////////////////////////////////////////////////
/** @file nchallenge.hpp
 *  @details Header file 
 *  @authors Andrés Balaguera-Antolinez 2025
 */
 // ********************************************
#include <thread>
extern "C" {
  #include <isa-l.h>
}
#include <immintrin.h>

// **************************************************************************
void print_openssl_error() {
  unsigned long err_code;
  while ((err_code = ERR_get_error()) != 0) {
      char *err_msg = ERR_error_string(err_code, nullptr);
      std::cerr << "OpenSSL Error: " << err_msg << std::endl;
  }
}
// **************************************************************************
// Initialize OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}
// **************************************************************************
// Clean up OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}
// **************************************************************************
// Create TCP socket to host:port
int create_socket(const std::string& host, int port) {
    struct hostent* hp = gethostbyname(host.c_str());
    if (!hp) { perror("gethostbyname"); exit(1); }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(1); }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(sock);
        exit(1);
    }
    return sock;
}
// **************************************************************************
// SHA‑1 and hex encode
std::string sha1_hex(const std::string& input) {
  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
  std::ostringstream oss;
  for (auto c : digest)
      oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
  return oss.str();
}
// **************************************************************************
std::string sha1_hex_n(const std::string& input) { //new suggestion, seems though to be slower
  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
  // Directly construct the hex string without using ostringstream
  std::string result;
  result.reserve(SHA_DIGEST_LENGTH * 2);  // Reserve space for hex output (2 characters per byte)
  for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
      // Convert each byte to hex and append to the result string
      result.push_back("0123456789abcdef"[digest[i] >> 4]);
      result.push_back("0123456789abcdef"[digest[i] & 0x0F]);
  }
  return result;
}
// **************************************************************************
std::string sha256_hex(const std::string& input) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
  std::ostringstream oss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
      oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  return oss.str();
}
// **************************************************************************
void sha256_batch_hex(const vector<string>& inputs, vector<string>& outputs) {
//#pragma omp parallel for
  for (size_t i = 0; i < inputs.size(); ++i) {
      outputs[i] = sha256_hex(inputs[i]);
  }
}
// **************************************************************************
void sha1_batch_hex_n(const vector<string>& inputs, vector<string>& outputs) {
  //#pragma omp parallel for
    for (size_t i = 0; i < inputs.size(); ++i) {
        outputs[i] = sha1_hex_n(inputs[i]);
    }

  }
// **************************************************************************
// Fast hex encoder for one digest using AVX2 lanes

static inline std::string hex_encode_sha1_avx2(const unsigned char* digest) {
  constexpr size_t digest_len = 20;
  constexpr size_t hex_len = digest_len * 2;

  const __m256i hex_chars = _mm256_setr_epi8(
      '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
      '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
  );
  alignas(32) char buf[hex_len + 1];
  // Load first 16 bytes (128 bits) into lower half of __m256i:
  __m128i bytes128 = _mm_loadu_si128((const __m128i*)digest); // 16 bytes
  // Expand to 256 bits with zero upper half
  __m256i bytes = _mm256_cvtepu8_epi16(bytes128); // This expands 16 bytes to 16 16-bit integers, but not what we want for hex
  // Actually _mm256_cvtepu8_epi16 produces 16 16-bit values from 16 bytes (128-bit input) - but the problem is it's 16-bit integers, not bytes. So maybe better:
  // Instead, do this:
  __m256i bytes256 = _mm256_zextsi128_si256(bytes128); // zero-extend lower 128 bits into 256 bits
  // Compute low and high nibbles
  __m256i lo = _mm256_and_si256(bytes256, _mm256_set1_epi8(0x0F));
  __m256i hi = _mm256_and_si256(_mm256_srli_epi16(bytes256, 4), _mm256_set1_epi8(0x0F));
  __m256i hex1 = _mm256_shuffle_epi8(hex_chars, hi);
  __m256i hex2 = _mm256_shuffle_epi8(hex_chars, lo);
  alignas(32) char tmp[32];
  // Store hex1 and hex2 to tmp buffers
  _mm256_store_si256((__m256i*)tmp, hex1);
  for (int i = 0; i < 16; ++i) {
      buf[2*i] = tmp[i];
  }
  _mm256_store_si256((__m256i*)tmp, hex2);
  for (int i = 0; i < 16; ++i) {
      buf[2*i + 1] = tmp[i];
  }
  // Process remaining 4 bytes scalar
  for (int i = 16; i < 20; ++i) {
      unsigned char b = digest[i];
      buf[2*i]     = "0123456789abcdef"[b >> 4];
      buf[2*i + 1] = "0123456789abcdef"[b & 0xF];
  }
  buf[hex_len] = '\0';  // Null terminate
  return std::string(buf);
}
/*
    First 16 bytes: loaded with _mm_loadu_si128 (128 bits), then zero-extended to 256-bit for AVX2 shuffle.
    hex1 and hex2 hold ASCII characters for high and low nibbles respectively.
    We write those to buf alternating for each nibble.
    Last 4 bytes: scalar loop converting them to hex.
    Buffer is null-terminated.
*/
// **************************************************************************
// **************************************************************************
// **************************************************************************
#ifdef USE_SHA256
static inline std::string hex_encode_sha256_avx2(const unsigned char* digest) {
  constexpr size_t digest_len = 32;
  constexpr size_t hex_len = digest_len * 2;

  const __m256i hex_chars = _mm256_setr_epi8(
      '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
      '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
  );

  alignas(32) char buf[hex_len + 1];

  // Load all 32 digest bytes into a 256-bit AVX2 register
  __m256i bytes = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(digest));

  // Extract high and low nibbles
  __m256i lo = _mm256_and_si256(bytes, _mm256_set1_epi8(0x0F));
  __m256i hi = _mm256_and_si256(_mm256_srli_epi16(bytes, 4), _mm256_set1_epi8(0x0F));

  // Lookup ASCII hex characters
  __m256i hex_hi = _mm256_shuffle_epi8(hex_chars, hi);
  __m256i hex_lo = _mm256_shuffle_epi8(hex_chars, lo);

  // Interleave high and low nibbles
  alignas(32) char hex_hi_bytes[32];
  alignas(32) char hex_lo_bytes[32];
  _mm256_store_si256(reinterpret_cast<__m256i*>(hex_hi_bytes), hex_hi);
  _mm256_store_si256(reinterpret_cast<__m256i*>(hex_lo_bytes), hex_lo);

  for (int i = 0; i < 32; ++i) {
      buf[2 * i]     = hex_hi_bytes[i];
      buf[2 * i + 1] = hex_lo_bytes[i];
  }

  buf[hex_len] = '\0';
  return std::string(buf);
}

// Batch hashing function. This is the faster function.
void sha256_simd_batch(const std::vector<std::string>& inputs,
  std::vector<std::string>& outputs) {
    size_t n = inputs.size();
    outputs.resize(n);
    // Do not use pragma omp parallel for if this used inside a parallel region,
    for (size_t i = 0; i < n; ++i) {
    outputs[i] = sha256_hex_fast(inputs[i]);
    }

  }
#endif

// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// Hash one input -> hex string
std::string sha1_hex_fast(const std::string& input) {
  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1((const unsigned char*)input.data(), input.size(), digest);
#ifdef __AVX2__
  return hex_encode_sha1_avx2(digest);
#else
 std::string s;
  s.reserve(40);
  for(int i=0;i<20;i++){
      s += "0123456789abcdef"[digest[i]>>4];
      s += "0123456789abcdef"[digest[i]&0xF];
  }
  return s;
#endif
}

std::string sha256_hex_fast(const std::string& input) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);

#ifdef __AVX2__
  return hex_encode_sha256_avx2(digest);  // You must define this if using AVX2
#else
  std::string s;
  s.reserve(64);  // SHA-256 hex is 64 characters
  static const char* hex = "0123456789abcdef";
  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
      s += hex[digest[i] >> 4];
      s += hex[digest[i] & 0xF];
  }
  return s;
#endif
}


// Batch hashing function. This is the faster function.
void sha1_simd_batch(const std::vector<std::string>& inputs,
                   std::vector<std::string>& outputs) {
  size_t n = inputs.size();
  outputs.resize(n);
// Do not use pragma omp parallel for if this used inside a parallel region,
  for (size_t i = 0; i < n; ++i) {
      outputs[i] = sha1_hex_fast(inputs[i]);
  }
}


