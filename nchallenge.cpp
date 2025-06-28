////////////////////////////////////////////////////////////////////////////
/** @file nchallenge.cpp
 *  @brief Exasol challenge
 *  @details 
    Compile with make nchall     
    Execute as 
    ./challenge.exe HOST PORT KEY for communication or
    ./challenge.exe diff for testing pow using differnet difficulty-level (diff)
 *  @authors Andrés Balaguera-Antolinez 2025
 */
 // ********************************************
#include "/home/balaguera/Challenge/nchallenge.hpp"



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
string solve_pow_batched(string &pads, string &authdata, bool &signal, int difficulty)
{
  string solution;
  atomic<bool> solution_found(false); // Use thread-safe information

#ifdef TIME_OUT
  auto start_time = chrono::high_resolution_clock::now();
#endif    


#ifdef USE_OMP
#pragma omp parallel shared(solution_found) 
  {
   int jthread=omp_get_thread_num();
#else
  int jthread=0;
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

      for (int i = 0; i < BATCH_SIZE ; ++i) // ALlocate hashes
        hashes[i] = sha1_hex(suffix[i] + authdata);

      bool local_found = false;
      for (int i = 0; i < BATCH_SIZE && !local_found; ++i) {
#ifdef DEBUG
      static thread_local int debug_counter = 0;
      if (++debug_counter % 100 == 0) {
          cout << "Thread " << jthread << " testing: " << suffix[i] << " → " << hashes[i].substr(0, 12) << "\n";
      }

#endif       
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
            local_found = true; // prevent duplicate prints
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

#ifdef USE_OMP 
    int nProcessors = omp_get_max_threads();
    cout<<CYAN<<"Using OpenMP with "<<nProcessors<<" processors for POW"<<RESET<<endl;
    omp_set_num_threads(nProcessors);
#endif

  int counter_ind=0;
  bool dec = true;
  bool signal_out=false;
  char char_pad='0';  
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
            string pads = pad(diff,char_pad);           
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


