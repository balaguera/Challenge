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
// Preproc definitions.
/**
 * @brief Define to use openmp
*/
#define USE_OMP  // Define to use OMP
// ********************************************
/**
 * @brief Define to test POW. When undef, fill code to communicate with server is active. 
*/
//#define TEST_POW 
// ********************************************
/**
 * @brief Define to stop code after a given time_window. Active with def and undef TEST_POW
*/
//#define TIME_OUT 
// ********************************************
#ifdef TEST_POW
/**
 * @brief Use a known solution for POW after some running time set by NEW_SOLUTION_TIME.
 * @details Solutions are found for a particular authdata and hence this applies for TEST_POW enabled, not in real communiciations.
*/
//#define USE_SOLUTION 
#endif
// ********************************************
/**
 * @brief Define to compare perforamnces of some randoms string generation and hash
*/
//#define  BENCHMARK
// ********************************************
#define USE_SIMD


// ********************************************
/**
 * @brief Define to write on screen some data ehen searching the solution for pow
*/
//#define DEBUG
// ********************************************
#define _USE_COLORS_
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
#ifdef TIME_OUT
/**
 * @brief Time window allowed for the process (mainly POW), in secs
*/
constexpr int TIME_WINDOW = 7190; // Two hours - 10 secs 
#endif
// **************************************************************************
#ifdef NEW_SEED
/**
 * @brief Time window allowed for the process (mainly POW), in secs before chosing a new seed
 * @details Using a new seed won´t help much if the initial seeds are well distirbuted.
*/
constexpr int TIME_WINDOW_NEW_SEED = 180; //  
#endif
// **************************************************************************
#ifdef USE_SOLUTION
/**
 * @brief Time window allowed for the process (mainly POW), in secs before chosing one found solution
*/
constexpr int NEW_SOLUTION_TIME = 20; //  
#endif
// **************************************************************************
#ifdef BENCHMARK
/**
 * @brief Number of calculatios to copmpare hases and random geenerator
*/
constexpr int STEPS_TEST = 500000; 
#endif
// **************************************************************************
/**
 * @brief  Valid UTF-8 characters 
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
/**
 * @brief  Set of solutions 
 * @details Found for difficulty = 9 using the authdata provided by the Exasol server
*/
const vector<string> solutions= {
    "é);;Fb%a7B1m", 
    "6ùmIRb_áLcJl", 
    "A6L6+cC-p!wì"};

// **************************************************************************
/**
 * @brief Random string generator.
*/
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
/**
 * @brief Random string generator.
 * @details This shows similar efficiency as random_string(rng)
*/
string random_string_b(gsl_rng* gBaseRand) { 
  std::string str(STRING_LENGTH, 0);
  for (int i = 0; i < STRING_LENGTH; ++i)
      str[i] = static_cast<char>(gsl_rng_uniform_int(gBaseRand, 256));
  return str;
}
// **************************************************************************
/**
 * @brief Returns a well-spread 64-bit seed per thread 
*/
ULONG get_seed(int thread, int difficulty)
 {
  using namespace std::chrono;
  auto now = high_resolution_clock::now().time_since_epoch().count();
  uint64_t pid = static_cast<uint64_t>(getpid());
  uint64_t base_seed = static_cast<uint64_t>(now) ^ pid;
  const uint64_t GOLDEN_RATIO = 0x9e3779b97f4a7c15ULL;
  return base_seed *difficulty + thread * GOLDEN_RATIO;
}
// **************************************************************************

