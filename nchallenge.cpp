////////////////////////////////////////////////////////////////////////////
/** @file challenge.cpp
 *  @brief Exasol challenge
 *  @details 
    Compile with make chall     
    Execute as 
    ./challenge.exe HOST PORT KEY DI

 *  @authors Andrés Balaguera-Antolinez
 */
 // ********************************************
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

// ********************************************

#define USE_OMP  // Define to use OMP
#define TEST_POW // To test POW
#define TIME_OUT // To stop code after a give time_window
#undef  BENCHMARK
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
constexpr int BATCH_SIZE = 32; 
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
void test_random() // Test differnet GSL random number generators applied to random strings
{
    cout<<GREEN<<"TESTING RANDOM"<<RESET<<endl;
    int jthread=1;//omp_get_thread_num();
    ULONG seed = get_seed(jthread,1);    // If in debug mode (available under TEST_POW), all threads share the same seed, hence solution is always the same found by the same thread
    gsl_rng *gBaseRand =gsl_rng_alloc(gsl_rng_mt19937); //(gsl_rng_mt19937); // gsl_rng_ranlxs0 is faster
    gsl_rng_set (gBaseRand, seed);

    time_t start_1; 
    time_t end_allt;

    time(&start_1);
    for(ULONG i=0;i<STEPS_TEST;++i)
      string suffix=random_string(gBaseRand); //Short random string, server accepts all utf-8 characters:
    time(&end_allt);
    float diffe=static_cast<float>(STEPS_TEST)/difftime(end_allt,start_1);
    cout<<YELLOW<<"gsl_rng_mt19937 done in "<<difftime(end_allt,start_1)<<" seconds. "<<diffe<<" rans/secs "<<RESET<<endl;
    gsl_rng_free(gBaseRand);

    gBaseRand =gsl_rng_alloc(gsl_rng_ranlxs0);
    gsl_rng_set (gBaseRand, seed);
    time(&start_1);
    for(ULONG i=0;i<STEPS_TEST;++i)
      string suffix=random_string(gBaseRand); //Short random string, server accepts all utf-8 characters:
    time(&end_allt);
    diffe=static_cast<float>(STEPS_TEST)/difftime(end_allt,start_1);
    cout<<YELLOW<<"gsl_rng_ranlxs0 done in "<<difftime(end_allt,start_1)<<" seconds. "<<diffe<<" rans/secs "<<RESET<<endl;
    gsl_rng_free(gBaseRand);


    gBaseRand =gsl_rng_alloc(gsl_rng_ranlux);
    gsl_rng_set (gBaseRand, seed);
    time(&start_1);
    for(ULONG i=0;i<STEPS_TEST;++i)
      string suffix=random_string(gBaseRand); //Short random string, server accepts all utf-8 characters:
    time(&end_allt);
    diffe=static_cast<float>(STEPS_TEST)/difftime(end_allt,start_1);
    cout<<YELLOW<<"gsl_rng_ranlux done in "<<difftime(end_allt,start_1)<<" seconds. "<<diffe<<" rans/secs "<<RESET<<endl;
    gsl_rng_free(gBaseRand);


  }

// **************************************************************************
void test_hash(){

  cout<<GREEN<<"TESTING HASH"<<RESET<<endl;

  vector<string> batch_inputs(STEPS_TEST, "51sdas6sdefs3aaaaa");
 vector<string> hashes(STEPS_TEST);

 time_t start_1; 
 time_t end_allt;

 time(&start_1);
 for(ULONG i=0;i<STEPS_TEST;++i)
    string ss=sha1_hex(batch_inputs[i]);
 time(&end_allt);
 float diffe=static_cast<float>(STEPS_TEST)/difftime(end_allt,start_1);
 cout<<YELLOW<<"sha1_hex done in "<<difftime(end_allt,start_1)<<" seconds. "<<diffe<<"  hash/secs "<<RESET<<endl;

 time(&start_1);
 for(ULONG i=0;i<STEPS_TEST;++i)
    string ss=sha1_hex_n(batch_inputs[i]);
 time(&end_allt);
 diffe=static_cast<float>(STEPS_TEST)/difftime(end_allt,start_1);
 cout<<YELLOW<<"sha1_hex_n done in "<<difftime(end_allt,start_1)<<" seconds. "<<diffe<<"  hash/secs "<<RESET<<endl;

  time(&start_1);
  sha256_batch_hex(batch_inputs, hashes);
  time(&end_allt);
  diffe=static_cast<float>(STEPS_TEST)/difftime(end_allt,start_1);
  cout<<YELLOW<<"sha256_batch_hex done in "<<difftime(end_allt,start_1)<<" seconds. "<<diffe<<"  hash/secs "<<RESET<<endl;


}


// **************************************************************************
// **************************************************************************

string solve_pow(string &pads, string &authdata, atomic<bool>&solution_found, int &counter_ind)
{
  string solution;
#ifdef USE_OMP 
#pragma omp parallel shared(solution_found, counter_ind) 
  {
    int jthread=omp_get_thread_num();
    gsl_rng *gBaseRand =gsl_rng_alloc (gsl_rng_mt19937);
    ULONG seed = get_seed(jthread,1);    // If in debug mode (available under TEST_POW), all threads share the same seed, hence solution is always the same found by the same thread
    gsl_rng_set (gBaseRand, seed);//Add the counter to the seed
#else
    gsl_rng *gBaseRand =gsl_rng_alloc (gsl_rng_ranlxs0);
    gsl_rng_set (gBaseRand,time(0) ^ counter_ind ^ getpid());//Add the counter to the seed
#endif
   int local_counter = 0;
#ifdef USE_OMP 
  while (!solution_found.load()) {
#endif
    // The exercise has been set to difficulty=9
    // We are looking for a hash output (from SHA1(authdata + suffix)) 
    // that begins with 9 leading zeroes in hexadecimal. That's a brute-force 
    // search problem, and the runtime grows exponentially with difficulty.
    string suffix=random_string(gBaseRand); //Short random string, server accepts all utf-8 characters:
    string cksum_in_hex = sha1_hex(authdata+suffix);  //Hash the random sufix and the authdata
#ifdef USE_OMP 
#pragma omp atomic
#endif
    counter_ind++;
    local_counter++;
    if(cksum_in_hex.starts_with(pads)) {          // Check if the checksum has enough (i.e 9in this case) leading zeros
#ifdef USE_OMP 
      if(!solution_found.exchange(true)){
#pragma omp critical
       {
         solution=suffix;
         cout << CYAN << "POW solution found by thread " << jthread
                     << " after " << counter_ind << " total attempts ("
                     << local_counter << " local). Suffix: " << suffix
                     << " Checksum: " << cksum_in_hex << RESET << endl;
       }
     } 
#else
     cout<<CYAN<<"Sending POW solution found after "<<counter_ind<<" attempts. Suffix : "<<suffix<<"  Checksum "<<cksum_in_hex<<RESET<<endl;
#endif
    } // closes if 
#ifdef USE_OMP 
  } // closes while (!solution_found.load()
#endif
  gsl_rng_free(gBaseRand);
#ifdef USE_OMP 
 } // closes parallel region
#endif    
 return solution;
}
// **************************************************************************
string solve_pow_batched(string &pads, string &authdata, bool &signal, int difficulty)
{
  string solution;
  atomic<bool> solution_found(false); // Use thread-safe information

#ifdef TIME_OUT
  auto start_time = chrono::high_resolution_clock::now();
#endif    
  int jthread=1;

#ifdef USE_OMP
#pragma omp parallel 
  {
    jthread=omp_get_thread_num();
#endif
    gsl_rng *gBaseRand =gsl_rng_alloc(gsl_rng_mt19937); 
    gsl_rng_set (gBaseRand, get_seed(jthread, difficulty));

    vector<std::string> suffix(BATCH_SIZE);
    vector<std::string> hashes(BATCH_SIZE);

    while (!solution_found.load(std::memory_order_acquire)){

#ifdef TIME_OUT
      auto end_time = chrono::high_resolution_clock::now();
      if(chrono::duration<double>(end_time-start_time).count()>=TIME_WINDOW){
        signal=true;
        break;
      }
#endif    

      for (int i = 0; i < BATCH_SIZE; ++i) // Allocate the ranodmd chains
        suffix[i] = random_string(gBaseRand);

 //   vector<std::string> inputs(BATCH_SIZE);
//      for (int i = 0; i < BATCH_SIZE; ++i)  // Allocate random plus autdata
//        inputs[i] = suffix[i] + authdata;

// if sha256_batch_hex is parallelized (see above), 
// we run into problems for we are are already in a parallel section. So better use sha1_hex directly 
// in which case we can avoid the use of input[]
//     sha256_batch_hex(inputs, hashes); 
      for (int i = 0; i < BATCH_SIZE; ++i) // ALlocate hashes
        hashes[i] = sha1_hex(suffix[i] + authdata);

      for (int i = 0; i < BATCH_SIZE; ++i) {
        if(hashes[i].starts_with(pads)) {// Check if the checksum has enough (i.e 9 in this case) leading zeros.Uses C++20 standard library function 
          bool expected=false;
          if(solution_found.compare_exchange_strong(expected,true,std::memory_order_acq_rel)){
#pragma omp critical
            {
              solution=suffix[i];
              cout<<endl;
              cout << CYAN << "POW solution found by thread " << jthread <<endl;
              cout<<"Suffix: " << suffix[i]<<endl;
              cout<<"Checksum: " << hashes[i] << RESET << endl;
            }
            break;
          }
        } 
      }
    }
  gsl_rng_free(gBaseRand);
#ifdef USE_OMP
} 
#endif

return solution;
}

// **************************************************************************
void test_solve_pow_b(bool select) // Bench the combnation of random and hash
{

  cout<<GREEN<<"TESTING SOLVE_POW"<<RESET<<endl;
  time_t start_1; 
  time(&start_1);
 
   int jthread=0;//omp_get_thread_num();
   gsl_rng *gBaseRand =gsl_rng_alloc(gsl_rng_mt19937); 
   gsl_rng_set (gBaseRand, get_seed(jthread,1));
   string authdata="lkk5sdf14313fg12fdg31";// some test
   vector<std::string> suffix(BATCH_SIZE);
   vector<std::string> hashes(BATCH_SIZE);
   if(select)
   {
    for(ULONG i=0;i<STEPS_TEST;++i){
      for (int i = 0; i < BATCH_SIZE; ++i)
        suffix[i] = random_string(gBaseRand);
      for (int i = 0; i < BATCH_SIZE; ++i) 
        hashes[i] = sha1_hex(suffix[i] + authdata);
     }
    }
    else {
      vector<std::string> inputs(BATCH_SIZE);
      for(ULONG i=0;i<STEPS_TEST;++i){
        for (int i = 0; i < BATCH_SIZE; ++i)
          suffix[i] = random_string(gBaseRand);
        for (int i = 0; i < BATCH_SIZE; ++i) 
          inputs[i] = suffix[i] + authdata;
        sha256_batch_hex(inputs, hashes);
      }
    }
  gsl_rng_free(gBaseRand);
   time_t end_allt;
  time(&end_allt);
  float diffe=static_cast<float>(STEPS_TEST)/difftime(end_allt,start_1);
  if(select)cout<<YELLOW<<__PRETTY_FUNCTION__<<" sha1_hex done in "<<difftime(end_allt,start_1)<<" seconds. "<<diffe<<"  operations/secs "<<RESET<<endl;
  else cout<<YELLOW<<__PRETTY_FUNCTION__<<" sha256_batch_hex done in "<<difftime(end_allt,start_1)<<" seconds. "<<diffe<<"  operations/secs "<<RESET<<endl;
}



// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************
// **************************************************************************

int main(int argc, char** argv) {


#ifndef TEST_POW
  if (argc != 4) {
    std::cerr << "Usage: ./code <host> <port> <pem_file>\n";
    return 1;
  }
#else
  if (argc != 2) {
    std::cerr << "Usage: ./code <diff> "<<endl;
    return 1;
  }
#endif

  time_t time_all;
  time(&time_all);
  cout<<endl;
  cout<<YELLOW<<"Starting at "<<ctime(&time_all)<<RESET<<endl;

  cout<<BLUE<<"================================="<<endl;
  cout<<"TSL challenge"<<endl;
  cout<<"================================="<<RESET<<endl;

  auto start_all = chrono::high_resolution_clock::now();

#ifdef TIME_OUT
  cout<<YELLOW<<"Timeout set to "<<TIME_WINDOW<<" secs "<<RESET<<endl;
#endif
  cout<<endl;

#ifdef BENCHMARK
  test_hash();
  test_random();
  test_solve_pow_b(0);
  test_solve_pow_b(1);
  exit(1);
#endif

#ifndef TEST_POW
    string host = argv[1];
    int port = std::stoi(argv[2]);
    string pem = argv[3];

    cout<<CYAN<<"Connecting to host      : "<<RESET<<host<< endl;
    cout<<CYAN<<"Port                    : "<<RESET<<port<< endl;
    cout<<CYAN<<"Key and certificate at  : "<<RESET<<pem<< endl;

    init_openssl();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return 1; }
    if (SSL_CTX_use_certificate_file(ctx, pem.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, pem.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    int sock = create_socket(host, port);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    cout << "TLS handshake succeeded using cipher: "<< SSL_get_cipher(ssl) <<endl;

    // Client data for replies
    struct {
        string name="Andres B", mailnum="2", mail1="abalant@gmail.com", mail2="";
        string skype="balant", birthdate="02.10.77", country="Spain";
        string addrline1="Camino el Ave 168 D", addrline2="38208 La Torre";
        string addrnum="2";
    } dc;

   // Read / write loop
    char buf[4096];
#endif    

    char input_char = '0';
#ifdef USE_OMP 
    int nProcessors = omp_get_max_threads();
    cout<<CYAN<<"Using OpenMP with "<<nProcessors<<" processors for POW"<<RESET<<endl;
    omp_set_num_threads(nProcessors);
#endif

  int counter_ind=0;
  bool dec = true;
  bool signal_out=false;

#ifdef TEST_POW  
  cout<<BLUE<<"-------------POW TEST--------------"<<RESET<<endl;
  string sdiff = argv[1];
  int diff = atoi(sdiff.c_str());
  cout<<CYAN<<"Difficulty: "<<diff<<RESET<<endl;
#else
  cout<<BLUE<<"-------------COMMUNICATION--------------"<<RESET<<endl;
#endif
  


#ifndef TEST_POW
      while (dec) {
        int bytes = SSL_read(ssl, buf, sizeof(buf)-1);
        if (bytes <= 0) break;
        buf[bytes] = '\0';
        std::string resp(buf);
        std::istringstream iss(resp);
        std::string cmd;
        iss >> cmd;
        std::string authdata;
        std::string edata;
        if (cmd == "HELO"){
          cout<<GREEN<<cmd<<RESET<<endl;
          SSL_write(ssl, "EHLO\n", 5);
        }
          else if (cmd == "POW") {
#else
      while(dec){
        std::string cmd="POW";
        if (cmd == "POW") {
#endif
#ifndef TEST_POW
            cout<<GREEN<<cmd<<RESET<<endl;
            int diff;
            iss >> authdata>>diff;
            cout<<GREEN<<"Difficulty = "<<diff<<RESET<<"  authdata = "<<authdata<<RESET<<endl;
#else
            string authdata="zhLjlDmDPamQVpQZlWZilpBvWEHKFApzkQwDsFnpAWBdrxvstzcOFcAxnQUITpZF";
#endif
            string pads = pad(diff,input_char);           
//            string sol=solve_pow(pads,authdata,solution_found, counter_ind);
            string sol=solve_pow_batched(pads,authdata,signal_out, diff);
            dec=false;
#ifdef TIME_OUT
            if(true==signal_out)
              break;
#endif
           
#ifndef TEST_POW
            SSL_write(ssl, sol.c_str(), sol.size());
#endif
          }
#ifndef TEST_POW
          else if (cmd == "ERROR") {
              cerr<<"ERROR: "<<resp.substr(6)<<endl;
  //          SSL_write(ssl, "ERROR: "+ edata+ "\n", 5);
            break;
          }
        else if (cmd == "NAME") {
            iss >> authdata;
            string reply = sha1_hex(authdata + dc.name) + " " + dc.name + "\n";
            SSL_write(ssl, reply.c_str(), reply.size());
        }
        else if (cmd == "MAILNUM") {
            iss >> authdata;
            string reply = sha1_hex(authdata + dc.mailnum) + " " + dc.mailnum + "\n";
            SSL_write(ssl, reply.c_str(), reply.size());
        }
        else if (cmd == "MAIL1") {
            iss >> authdata;
            string reply = sha1_hex(authdata + dc.mail1) + " " + dc.mail1 + "\n";
            SSL_write(ssl, reply.c_str(), reply.size());
        }
        else if (cmd == "MAIL2") {
            iss >> authdata;
            string reply = sha1_hex(authdata + dc.mail2) + " " + dc.mail2 + "\n";
            SSL_write(ssl, reply.c_str(), reply.size());
        }
        else if (cmd == "SKYPE") {
            iss >> authdata;
            string reply = sha1_hex(authdata + dc.skype) + " " + dc.skype + "\n";
            SSL_write(ssl, reply.c_str(), reply.size());
        }
        else if (cmd == "BIRTHDATE") {
            iss >> authdata;
            string reply = sha1_hex(authdata + dc.birthdate) + " " + dc.birthdate + "\n";
            SSL_write(ssl, reply.c_str(), reply.size());
        }
        else if (cmd == "COUNTRY") {
            iss >> authdata;
            string reply = sha1_hex(authdata + dc.country) + " " + dc.country + "\n";
            SSL_write(ssl, reply.c_str(), reply.size());
        }
        else if (cmd == "ADDRNUM") {
            iss >> authdata;
            string reply = sha1_hex(authdata + dc.addrnum) + " " + dc.addrnum + "\n";
            SSL_write(ssl, reply.c_str(), reply.size());
        }
        else if (cmd == "ADDRLINE1") {
            iss >> authdata;
            string reply = sha1_hex(authdata + dc.addrline1) + " " + dc.addrline1 + "\n";
            SSL_write(ssl, reply.c_str(), reply.size());
        }
        else if (cmd == "ADDRLINE2") {
            iss >> authdata;//            std::string sol = solve_pow(diff, authdata);
            string reply = sha1_hex(authdata + dc.addrline2) + " " + dc.addrline2 + "\n";
            SSL_write(ssl, reply.c_str(), reply.size());
        }
        else if (cmd == "END") {
            SSL_write(ssl, "OK\n", 3);
            break;
        }
        else {
            cout << "Unexpected server command: " << cmd << "\n";
            break;
        }
#endif        
    }

    auto end_all = chrono::high_resolution_clock::now();

#ifndef TEST_POW
    // Cleanup
    SSL_shutdown(ssl);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    cout << "Connection closed."<< endl;
#endif        
cout<<endl;

#ifdef TIME_OUT
  if(false==signal_out)
#endif
  cout<<YELLOW<<"Solution found in "<<chrono::duration<double>(end_all-start_all).count()<<" seconds"<<RESET<<endl;
  #ifdef TIME_OUT
  else
    cout<<RED<<"TIME OUT!. Solution not found in allowed time lapse (" <<TIME_WINDOW<<" s). Try to decrease difficulty or increase time window."<<RESET<<endl;
#endif
  cout<<endl;
  return 0;
}


