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
 #include "/home/balaguera/Challenge/ssl.hpp"

 using namespace std;

// **************************************************************************
// **************************************************************************
#ifdef BENCHMARK
void test_random() // Test differnet GSL random number generators applied to random strings
{
    cout<<endl;
    cout<<GREEN<<"TESTING RANDOM"<<RESET<<endl;
    int jthread=1;//omp_get_thread_num();
    ULONG seed = get_seed(jthread,1);    // If in debug mode (available under TEST_POW), all threads share the same seed, hence solution is always the same found by the same thread
    gsl_rng *gBaseRand =gsl_rng_alloc(gsl_rng_mt19937); //(gsl_rng_mt19937); // gsl_rng_ranlxs0 is faster
    gsl_rng_set (gBaseRand, seed);

    time_t start_1; 
    time_t end_allt;

    auto start_time = chrono::high_resolution_clock::now();
    for(ULONG i=0;i<STEPS_TEST;++i)
      string suffix=random_string(gBaseRand); //Short random string, server accepts all utf-8 characters:
    auto end_time = chrono::high_resolution_clock::now();
    double difft=chrono::duration<double>(end_time-start_time).count();
    double diff =static_cast<float>(STEPS_TEST)/difft/1000000.;
    cout<<YELLOW<<"gsl_rng_mt19937 done in "<<difft<<" sec, "<<diff<<"  M-r/sec "<<RESET<<endl;
    gsl_rng_free(gBaseRand);

    gBaseRand =gsl_rng_alloc(gsl_rng_ranlxs0);
    gsl_rng_set (gBaseRand, seed);
    start_time = chrono::high_resolution_clock::now();
    for(ULONG i=0;i<STEPS_TEST;++i)
      string suffix=random_string(gBaseRand); //Short random string, server accepts all utf-8 characters:
    end_time = chrono::high_resolution_clock::now();
    difft=chrono::duration<double>(end_time-start_time).count();
    diff =static_cast<float>(STEPS_TEST)/difft/1000000.;
    cout<<YELLOW<<"gsl_rng_ranlxs0 done in "<<difft<<" sec, "<<diff<<" M-r/sec "<<RESET<<endl;
    gsl_rng_free(gBaseRand);

    gBaseRand =gsl_rng_alloc(gsl_rng_ranlux);
    gsl_rng_set (gBaseRand, seed);
    start_time = chrono::high_resolution_clock::now();
    for(ULONG i=0;i<STEPS_TEST;++i)
      string suffix=random_string(gBaseRand); //Short random string, server accepts all utf-8 characters:
    end_time = chrono::high_resolution_clock::now();    
    difft=chrono::duration<double>(end_time-start_time).count();
    diff =static_cast<float>(STEPS_TEST)/difft/1000000.;
    cout<<YELLOW<<"gsl_rng_ranux done in "<<difft<<" sec, "<<diff<<" M-r/sec "<<RESET<<endl;
    gsl_rng_free(gBaseRand);
  }

// **************************************************************************
void test_hash(){
  cout<<endl;
 cout<<GREEN<<"TESTING HASH"<<RESET<<endl;
 vector<string> batch_inputs(STEPS_TEST, "51sdas6sdefs3aaaaa");
 vector<string> hashes(STEPS_TEST);
 auto start_time = chrono::high_resolution_clock::now();

 for(ULONG i=0;i<STEPS_TEST;++i)
    string ss=sha1_hex(batch_inputs[i]);
 auto end_time = chrono::high_resolution_clock::now();
 double difft=chrono::duration<double>(end_time-start_time).count();
 double diff =static_cast<float>(STEPS_TEST)/difft/1000000.0;
 cout<<YELLOW<<"sha1_hex done in "<<difft<<" sec, "<<diff<<"  M-hash/sec "<<RESET<<endl;

 start_time = chrono::high_resolution_clock::now();
 for(ULONG i=0;i<STEPS_TEST;++i)
    string ss=sha1_hex_n(batch_inputs[i]);
 end_time = chrono::high_resolution_clock::now();
 difft=chrono::duration<double>(end_time-start_time).count();
 diff =static_cast<float>(STEPS_TEST)/difft/1000000.0;
 cout<<YELLOW<<"sha1_hex_n done in "<<difft<<" sec, "<<diff<<"  M-hash/sec "<<RESET<<endl;

 start_time = chrono::high_resolution_clock::now();
 for(ULONG i=0;i<STEPS_TEST;++i)
    string ss=sha256_hex(batch_inputs[i]);
 end_time = chrono::high_resolution_clock::now();
 difft=chrono::duration<double>(end_time-start_time).count();
 diff =static_cast<float>(STEPS_TEST)/difft/1000000.0;
 cout<<YELLOW<<"sha256_hex done in "<<difft<<" sec, "<<diff<<"  M-hash/sec "<<RESET<<endl;


 start_time = chrono::high_resolution_clock::now();
 sha256_batch_hex(batch_inputs, hashes);
 end_time = chrono::high_resolution_clock::now();
 difft=chrono::duration<double>(end_time-start_time).count();
 diff =static_cast<float>(STEPS_TEST)/difft/1000000.0;
 cout<<YELLOW<<"sha256_batch_hex done in "<<difft<<" sec, "<<diff<<"  M-hash/sec "<<RESET<<endl;


 start_time = chrono::high_resolution_clock::now();
 sha1_batch_hex_n(batch_inputs, hashes);
 end_time = chrono::high_resolution_clock::now();
 difft=chrono::duration<double>(end_time-start_time).count();
 diff =static_cast<double>(STEPS_TEST)/difft/1000000.0;
 cout<<YELLOW<<"sha1_batch_hex_n done in "<<difft<<" sec, "<<diff<<"  M-hash/sec "<<RESET<<endl;

 start_time = chrono::high_resolution_clock::now();
 sha1_simd_batch(batch_inputs, hashes);
 end_time = chrono::high_resolution_clock::now();
 difft=chrono::duration<double>(end_time-start_time).count();
 diff =static_cast<double>(STEPS_TEST)/difft/1000000.0;
 cout<<YELLOW<<"sha1_simd_batch done in "<<difft<<" sec, "<<diff<<"  M-hash/sec "<<RESET<<endl;


}
#endif
// **************************************************************************
// **************************************************************************
inline void send_response(SSL* ssl, const std::string& authdata, 
  const string& cmd, istringstream& iss, const string& value) {
  string message;
  iss >> message;
#ifdef USE_SHA1
  string reply = sha1_hex_n(authdata + message) + " " + value + "\n";
#else
  string reply = sha256_hex_fast(authdata + message) + " " + value + "\n";
#endif

  #ifdef DEBUG
  cout << GREEN << "Sending " << RESET <<cmd  << endl;
  cout << GREEN << "value: " << RESET<< value << endl;
  cout << GREEN << "authdata: " << RESET<< authdata << endl;
  cout << GREEN << "message " << RESET <<message <<endl;
  cout << GREEN << "reply " << RESET <<reply <<endl;
#endif
  SSL_write(ssl, reply.c_str(), reply.size());
#ifdef DEBUG
  cout << GREEN << "Done " << cmd << RESET << endl;
#endif
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
#ifdef USE_SHA1
  string cksum_in_hex = sha1_hex_n(authdata+suffix);  //Hash the random sufix and the authdata
#else
  string cksum_in_hex = sha256_hex(authdata+suffix);  //Hash the random sufix and the authdata
#endif
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
#ifdef BENCHMARK
void test_solve_pow_b(int select, int bash_size) // Bench the combnation of random and hash
{
  cout<<endl;
  cout<<GREEN<<"TESTING "<<__PRETTY_FUNCTION__<<" with "<<bash_size<<" as bash_size"<< RESET<<endl;
  auto start_time = chrono::high_resolution_clock::now();
 
   int jthread=0;//omp_get_thread_num();
   gsl_rng *gBaseRand =gsl_rng_alloc(gsl_rng_mt19937); 
   gsl_rng_set (gBaseRand, get_seed(jthread,1));
   string authdata="mENPJVIzNjmEeuLTYxvitBuyeMTnpblBqRXibFzJfwkbPnJPoUVILmZmuTURvFrE";// some test
   string known_test = "&2kkbP{:Uw{4";
   vector<std::string> suffix(bash_size);
   vector<std::string> hashes(bash_size);
   if(0==select)
   {
    cout<<"Using sha1_hex"<<endl;
    for(ULONG i=0;i<STEPS_TEST;++i){
      for (int i = 0; i < bash_size; ++i)
      suffix[i] =  "asc";//random_string(gBaseRand);
      for (int i = 0; i < bash_size; ++i) 
        hashes[i] = sha1_hex(authdata+suffix[i]);
     //   cout<<suffix[0]+authdata<<"  "<<hashes[0]<<endl;
     }
    }
    else if(1==select){
      cout<<"Using sha1_hex_n"<<endl;
      for(ULONG i=0;i<STEPS_TEST;++i){
       for (int i = 0; i < bash_size; ++i)
       suffix[i] =  "asc";//random_string(gBaseRand);
//       suffix[i] = random_string(gBaseRand);
       for (int i = 0; i < bash_size; ++i) 
        hashes[i] = sha1_hex_n(authdata+suffix[i]);
    //    cout<<suffix[0]+authdata<<"  "<<hashes[0]<<endl;
      }
    }
    else if(2==select){
      cout<<"Using sha256_batch_hex"<<endl;
      vector<std::string> inputs(bash_size);
      for(ULONG i=0;i<STEPS_TEST;++i){
        for (int i = 0; i < bash_size; ++i)
          suffix[i] =  "asc";//random_string(gBaseRand);
        for (int i = 0; i < bash_size; ++i) 
          inputs[i] =   authdata+suffix[i];
        sha256_batch_hex(inputs, hashes);
       //cout<<inputs[0]<<"  "<<hashes[0]<<endl;
      }
    }
    else if(3==select){
      cout<<"Using sha1_batch_hex"<<endl;
      vector<std::string> inputs(bash_size);
      for(ULONG i=0;i<STEPS_TEST;++i){
        for (int i = 0; i < bash_size; ++i)
          suffix[i] =  "asc";//random_string(gBaseRand);
        for (int i = 0; i < bash_size; ++i) 
        inputs[i] =   authdata+suffix[i];
        sha1_batch_hex_n(inputs, hashes);
   //    cout<<inputs[0]<<"  "<<hashes[0]<<endl;
      }
    }

    else if(4==select){
      cout<<"Using sha1_simd_batch"<<endl;
      vector<std::string> inputs(bash_size);
      for(ULONG i=0;i<STEPS_TEST;++i){
        for (int i = 0; i < bash_size; ++i)
          suffix[i] = "asc";//random_string(gBaseRand);
        for (int i = 0; i < bash_size; ++i) 
        inputs[i] =   authdata+suffix[i];
        sha1_simd_batch(inputs, hashes);
      //  cout<<inputs[0]<<"  "<<hashes[0]<<endl;
      }
    }

  gsl_rng_free(gBaseRand);

 
  auto end_time = chrono::high_resolution_clock::now();
  double difft=chrono::duration<double>(end_time-start_time).count();
  double diffe=static_cast<double>(STEPS_TEST)/difft/1000000.0;
  cout<<YELLOW<<__PRETTY_FUNCTION__<<diffe<<"  M-operations/secs "<<RESET<<endl;
}
#endif
// **************************************************************************
string solve_pow_batch(string &pads, string &authdata, bool &signal, int difficulty)
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
 
#if defined NEW_SEED || defined USE_SOLUTION
new_seed:
  auto start_time_new_seed = chrono::high_resolution_clock::now();
#endif
   gsl_rng_set (gBaseRand, get_seed(jthread, difficulty));

    while (!solution_found.load(std::memory_order_acquire)){

#ifdef TIME_OUT
      auto end_time = chrono::high_resolution_clock::now();
      if(chrono::duration<double>(end_time-start_time).count()>=TIME_WINDOW){
        signal=true;
        break;
      }
#endif    
#if defined NEW_SEED  || defined USE_SOLUTION
      auto end_time_new_seed = chrono::high_resolution_clock::now();
#endif    
#ifdef NEW_SEED
      if(chrono::duration<double>(end_time_new_seed-start_time_new_seed).count()>=TIME_WINDOW_NEW_SEED){
        if(jthread==0)cout<<GREEN<<"Chosing new seed"<<RESET<<endl;
        goto new_seed;
      }
#endif

  for (int i = 0; i < BATCH_SIZE; ++i) // Allocate the ranodmd chains
        suffix[i] = random_string(gBaseRand);

#ifdef USE_SOLUTION
    if(chrono::duration<double>(end_time_new_seed-start_time_new_seed).count()>=NEW_SOLUTION_TIME)
    {
#ifdef DEBUG
      if(jthread==0)cout<<GREEN<<"Fixing solution"<<RESET<<endl;
#endif
      int sel=gsl_rng_uniform_int(gBaseRand, solutions.size());
      for (int i = 0; i < BATCH_SIZE; ++i) // Allocate the ranodmd chains
        suffix[i] =solutions[sel];
    }
#endif    
    vector<string> inputs(BATCH_SIZE);
    for (int i = 0; i < BATCH_SIZE; ++i)  // Allocate random plus autdata
      inputs[i] =  authdata + suffix[i] ; // THhs order is important. First authdata

#ifdef USE_SIMD
#ifdef USE_SHA1
    sha1_simd_batch(inputs, hashes);
#else
    sha256_simd_batch(inputs, hashes);
#endif
#else
#ifdef USE_SHA1
      sha1_batch_hex_n(inputs, hashes); 
#else
     sha256_hex(inputs, hashes); 
#endif
#endif

      bool local_found = false;
      for (int i = 0; i < BATCH_SIZE && !local_found; ++i) {
#ifdef DEBUG_int
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
#ifdef DEBUG
            cout<<endl;
            cout << CYAN << "POW solution found by thread " << jthread <<endl;
            cout<<"Suffix: " << suffix[i]<<endl;
            cout<<"Checksum: " << hashes[i] << RESET << endl;
#endif
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

#ifdef NEW_SEED
  cout<<YELLOW<<"New seed is chosen after "<<TIME_WINDOW_NEW_SEED<<" secs "<<RESET<<endl;
#endif

#ifdef USE_SOLUTION
  cout<<YELLOW<<"Solution chosen from previus minig after "<<NEW_SOLUTION_TIME<<" secs "<<RESET<<endl;
#endif


  cout<<endl;

#ifdef BENCHMARK
  test_hash();
  test_random();
  test_solve_pow_b(0,16);
  test_solve_pow_b(1,16);
  test_solve_pow_b(2,16);
  test_solve_pow_b(3,16);
  test_solve_pow_b(4,16);
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
        string name="Andres Balaguera.", mailnum="2", mail1="abalant@gmail.com", mail2="balaguera-ext@iac.es";
        string skype="N/A", birthdate="02.10.1977", country="Spain";
        string addrline1="Camino Ave 168", addrline2="38208 LaLaguna";
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
#else
  cout<<BLUE<<"-------------COMMUNICATION--------------"<<RESET<<endl;
#endif
std::string authdata="";
  
#ifndef TEST_POW
      while (true) {
        int bytes = SSL_read(ssl, buf, sizeof(buf)-1);
        if (bytes <= 0) break;
        buf[bytes] = '\0';
        std::string resp(buf);
        std::istringstream iss(resp);
        std::string cmd;
        iss >> cmd;   //args[0]
        std::string authdata;
        std::string edata;
        if (cmd == "HELO"){
          cout<<GREEN<<"Sending "<<RESET<<cmd<<endl;
          SSL_write(ssl, "EHLO\n", 5);
        }
        else if (cmd == "POW") {
#else
      while(dec){
        std::string cmd="POW";
        if (cmd == "POW") {
#endif
#ifndef TEST_POW
          cout<<GREEN<<"Solving "<<RESET<<cmd<<endl;
          int diff=9; // Initialized to the value of the challenge. To be read in nay case.
          iss >> authdata>>diff; //args[1], args[2]
          cout<<GREEN<<"Difficulty = "<<RESET<<diff<<endl;
          cout<<GREEN<<"authdata = "<<RESET<<authdata<<endl;
#else
          string authdata="zhLjlDmDPamQVpQZlWZilpBvWEHKFApzkQwDsFnpAWBdrxvstzcOFcAxnQUITpZF";//Some data to test with
          cout<<GREEN<<"Difficulty = "<<RESET<<diff<<endl;
          cout<<GREEN<<"Authdata = "<<RESET<<authdata<<endl;
#endif
          string pads = string(diff, char_pad);        // Use c++20 feature   
          string sol = solve_pow_batch(pads,authdata,signal_out, diff);
//          cout<<GREEN<<"Solution = " <<RESET<<sol<<endl;
#ifdef TEST_POW
          dec=false;
#endif

#ifdef TIME_OUT
          if(true==signal_out)
            break;
#endif

#ifndef TEST_POW
            cout<<GREEN<<"Sending" <<RESET<<endl;
            string sol_and_end = sol + "\n";
            SSL_write(ssl, sol_and_end.c_str(), sol.size()+1);
            cout<<GREEN<<"Done" <<RESET<<endl;
#ifdef DEBUG_int
            cout<<BLUE<<"Check sh1_hex :"<<sha1_hex(authdata+sol)<<RESET<<endl;
            cout<<BLUE<<"Check sh1_hex_n :"<<sha1_hex_n(authdata+sol)<<RESET<<endl;
            cout<<BLUE<<"Check sh1_fast :"<<sha1_hex_fast(authdata+sol)<<RESET<<endl;
#endif
#endif
          }
#ifndef TEST_POW
          else if (cmd == "ERROR") {
              cerr<<"ERROR: "<<resp.substr(6)<<endl;
  //          SSL_write(ssl, "ERROR: "+ edata+ "\n", 5);
             break;
          }
        else if (cmd == "NAME") 
          send_response(ssl, authdata, cmd, iss, dc.name);

         else if (cmd == "MAILNUM") 
          send_response(ssl, authdata, cmd, iss, dc.mailnum);
       
        else if (cmd == "MAIL1") 
          send_response(ssl, authdata, cmd, iss, dc.mail1);
        
        else if (cmd == "MAIL2") 
          send_response(ssl, authdata, cmd, iss, dc.mail2);
        
        else if (cmd == "SKYPE") 
          send_response(ssl, authdata, cmd, iss, dc.skype);
        
        else if (cmd == "BIRTHDATE") 
          send_response(ssl, authdata, cmd, iss, dc.birthdate);
        
        else if (cmd == "COUNTRY") 
          send_response(ssl, authdata, cmd, iss, dc.country);
        
        else if (cmd == "ADDRNUM") 
          send_response(ssl, authdata, cmd, iss, dc.addrnum);
       
        else if (cmd == "ADDRLINE1") 
          send_response(ssl, authdata, cmd, iss, dc.addrline1);

        else if (cmd == "ADDRLINE2") 
          send_response(ssl, authdata, cmd, iss, dc.addrline2);
        
        else if (cmd == "END") {
           cout<<GREEN<<"END"<<RESET<<endl;
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

