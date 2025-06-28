////////////////////////////////////////////////////////////////////////////
/** @file nchallenge.hpp
 *  @details Header file 
 *  @authors Andrés Balaguera-Antolinez 2025
 */
 // ********************************************
#pragma once
#include <string>
#include <vector>
#include <math.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include <cassert>
#include <cfloat>
#include <stdlib.h>
#include <stdio.h>
#include <numeric>
#include <algorithm>
#include <ctime>
#include <cmath>
#include <cctype>
#include <iostream>
#include <fstream>
#include <sstream>
#include <optional>
#include <unistd.h> 
#include <atomic> 
#include <resolv.h>
#include <netdb.h>
#include <gsl/gsl_rng.h>
#include <gsl/gsl_randist.h>
#include <boost/uuid/detail/sha1.hpp>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <sys/time.h> 
#include <random>
#include <boost/uuid/detail/sha1.hpp>
#include <omp.h>
#include <atomic>
#include <chrono>

using namespace std;
using namespace chrono;

// ********************************************

#define USE_OMP  // Define to use OMP
#define TEST_POW // To test POW
#define TIME_OUT // To stop code after a give time_window
#undef  BENCHMARK
#define _USE_COLORS_
//#define DEBUG
// ********************************************
#ifdef _USE_COLORS_
/**
 * @brief Color Red
*/
#define RED     "\033[31m"      /* Red */
#else
#define RED   RESET
#endif
// ********************************************
#ifdef _USE_COLORS_
/**
 * @brief Color Green
*/
#define GREEN   "\033[32m"      /* Green */
#else
#define GREEN   RESET
#endif
// ********************************************
#define RESET   "\033[0m"
#define _USE_COLORS_
 /**
 * @brief Color Yellow
*/
#ifdef _USE_COLORS_
#define YELLOW  "\033[33m"      /* Yellow */
#else
#define YELLOW   RESET
#endif
// ********************************************
/**
 * @brief Color Blue
*/
#ifdef _USE_COLORS_
#define BLUE    "\033[34m"      /* Blue */
#else
#define BLUE   RESET
#endif
// ********************************************
/**
 * @brief Color Cyan
*/
#ifdef _USE_COLORS_
#define CYAN    "\033[36m"      /* Cyan */
#else
#define CYAN   RESET
#endif
// **************************************************************************
#define ULONG unsigned long
// **************************************************************************
/**
 * @brief Error status
*/
const int ERROR_STATUS = -1;
// **************************************************************************
/**
 * @brief Lengh of random string.
 * @details The string engs depends on the degreee of difficulty. Large difficulties need larger strings to increase entropy
*/
const int STRING_LENGTH = 12;
// **************************************************************************
/**
 * @brief Used to solve the Proof-of-Work. Tried 8, 16, 32
*/
constexpr int BATCH_SIZE = 2048; 
// **************************************************************************
/**
 * @brief Time window allowed for the process (mainly POW), in secs
*/
constexpr int TIME_WINDOW = 7200; // Two hours 

// **************************************************************************
/**
 * @brief Number of calculatios to copmpare hases and random geenerator
*/
constexpr int STEPS_TEST = 500000; 
// **************************************************************************
/**
 * @brief  Valid UTF-8 characters (you can expand this list) 
*/
const vector<string> ALPHA = {
  "A","B","C","D","E","F","G","H","I","J","K","L","M",
  "N","O","P","Q","R","S","T","U","V","W","X","Y","Z",
  "a","b","c","d","e","f","g","h","i","j","k","l","m",
  "n","o","p","q","r","s","t","u","v","w","x","y","z",
  "0","1","2","3","4","5","6","7","8","9",
  "!","@","#","$","%","^","&","*","(",")","-","_","=","+",
  "[","]","{","}",";",":","'",",","<",".",">","/","?",
  "á","é","í","ó","ú","ñ","ç","à","è","ì","ò","ù"
};
// **************************************************************************
string random_string(gsl_rng *gBaseRand) {
  int isize = ALPHA.size();
  string rstring;
  rstring.reserve(STRING_LENGTH * 3); // UTF-8 chars may be 2+ bytes
  for (int i = 0; i < STRING_LENGTH; ++i) {
      rstring += ALPHA[gsl_rng_uniform_int(gBaseRand, isize)];
  }
  return rstring;
}
// **************************************************************************
string random_string_b(gsl_rng* gBaseRand) { // This shows similar efficiency as random_string(rng)
  std::string str(STRING_LENGTH, 0);
  for (int i = 0; i < STRING_LENGTH; ++i)
      str[i] = static_cast<char>(gsl_rng_uniform_int(gBaseRand, 256));
  return str;
}
// **************************************************************************
string pad(int &per, char &lett) // Build a string of 'per' chars 'letters'
 { 
  vector<char>data;
  for(int i=0; i<per;++i)
    data.push_back(lett);
  string full;
  for(int i=0; i<per;++i)
    full+=data[i];
  return full;
}
// **************************************************************************
ULONG get_seed(int thread, int difficulty)// Returns a well-spread 64-bit seed per thread 
 {
  using namespace std::chrono;
  auto now = high_resolution_clock::now().time_since_epoch().count();
  uint64_t pid = static_cast<uint64_t>(getpid());
  uint64_t base_seed = static_cast<uint64_t>(now) ^ pid;
  const uint64_t GOLDEN_RATIO = 0x9e3779b97f4a7c15ULL;
  return base_seed *difficulty + thread * GOLDEN_RATIO;
}
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
// **************************************************************************
// **************************************************************************
