/* <ssl/ssl_threadsupport.h>

   ----------------------------------------------------------------------------
   Copyright 2015 OLA Mobile

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   ----------------------------------------------------------------------------

   Initializes SSL for multithreaded use and keeps shared state in a singleton. 
   Agnostic to whether it is a server or a client.
 */

#pragma once

#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <stdexcept>
#include <string>
#include <sstream>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <syslog.h>


namespace SSL_config {



  // vector of locks used by openSSL
  static std::mutex* locks {nullptr};
  static int nlocks{0};

  // Call back function used by openssl library to be thread safe
  static void locking_function(int mode, int n, 
			const char *file, int line){
    

    if (n >= nlocks){
      std::string filename{file};
      std::string error_string = "SSL Locks out of bounds in " +  
	filename + " at line: " + std::to_string(line);
      syslog(LOG_ERR, "SSL locks out of bound in %s at %d\n", file, line);
      throw std::runtime_error(error_string);
    }
    
    if (mode & CRYPTO_LOCK) {
      locks[n].lock();
    } else {
      locks[n].unlock();
    }
    
  } // locking_function
  
  // Call back function also used by openssl thread safety
  static unsigned long id_function(void) {
    std::stringstream ss;
    ss << std::this_thread::get_id();
    return std::stoul(ss.str());
  } // id_function
  
  
  

  
  class TSSL_Init {
  public:
    static TSSL_Init& Instance(){
      //  thread safe in C++11
      static TSSL_Init theInstance;
      return theInstance;
    }

    SSL_CTX* get_ctx(){
      return ctx;
    }


  private:

    void LoadCertificates(SSL_CTX* local_ctx) {

      // set the local certificate from CertFile 
      std::string cert = "/home/mats/.ssh/ola_client.cert.pem";      
      if ( SSL_CTX_use_certificate_file(local_ctx, cert.c_str(), 
					SSL_FILETYPE_PEM) <= 0 ) {
	std::string errorStr = "Could not load certifiate: " + cert;
	syslog(LOG_ERR, "Could not load certificate: %s\n", cert.c_str());
	throw std::runtime_error(errorStr);
      }
      syslog(LOG_INFO, "Loaded SSL certificate: %s", cert.c_str());

      // set the private key from KeyFile (may be the same as CertFile) 
      std::string keyFile = "/home/mats/.ssh/www.olamobile.com.key.pem";
      if ( SSL_CTX_use_PrivateKey_file(local_ctx, keyFile.c_str(), 
				       SSL_FILETYPE_PEM) <= 0 ) {
	std::string errorStr = "Could not load key file: " + keyFile;
	syslog(LOG_ERR, "Could not load key file: %s\n", keyFile.c_str());
	throw std::runtime_error(errorStr);
      }
      syslog(LOG_INFO, "Set SSL Private key to: %s", keyFile.c_str());

      // verify private key 
      if ( !SSL_CTX_check_private_key(local_ctx) ) {
	std::string errorStr = 
	  "Private key does not match the public certificate";
	syslog(LOG_ERR, "Private key does not match the public certificate\n");
	throw std::runtime_error(errorStr);
      }
      syslog(LOG_INFO, "Verified private key");
    } // LoadCertificates
    

    SSL_CTX* InitCTX(void) {
      // create new method instance
      const SSL_METHOD *method = TLSv1_method();  // remove this when working
      
      // create new context from method 
      SSL_CTX *local_ctx = SSL_CTX_new(method); 
      
      if ( ctx == NULL ) {
	syslog(LOG_NOTICE, 
	       "All send and receive threads finished shutting down");
      }

      syslog(LOG_INFO, "Created new SSL context");

      return local_ctx;
    } // InitCTX

    // hidden constructor
    TSSL_Init() {
      // Initalize basic SSL and BIO stuff
      SSL_library_init();
      SSL_load_error_strings();  
      ctx = InitCTX();


      if (!SSL_CTX_use_certificate_chain_file(ctx, "/home/mats/ssl-cert/client.pem") != 1){
	syslog(LOG_ERR, "Failed to load client side certificates from file\n");
	throw std::runtime_error("Failed to load client side certificates from file");	
      }

      if (SSL_CTX_use_PrivateKey_file(ctx, "/home/mats/ssl-cert/client.pem", SSL_FILETYPE_PEM)){
	syslog(LOG_ERR, "Failed to load client privae key from file\n");
	throw std::runtime_error("Failed to load client private key from file");	
      }

#if 0
      //old code
      LoadCertificates(ctx); // load certs 

      SSL_CTX_set_verify_depth(ctx, 2);
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
      
      // Load trusted CA. 
      if (!SSL_CTX_load_verify_locations(ctx,"/home/mats/.ssh/ca-chain.cert.pem",NULL)) {
	syslog(LOG_ERR, "Failed to load trusted CA\n");
	throw std::runtime_error("Failed to load trusted CA");
      }
#endif

      nlocks = CRYPTO_num_locks();
      locks = new std::mutex[nlocks];
      if (locks){
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
      } else {
	syslog(LOG_ERR, "Failed to allocate memory for locks\n");
	throw std::runtime_error("Failed to allocate memory for locks");
      }

    } // TSSL_Init constructor

    //    TSSL_Init(TSSL_Init const&) = delete;

    ~TSSL_Init() {
      delete [] locks;
    }

    // Shared state
    SSL_CTX *ctx;              // SSL context

  };  // class TSSL_Init




} // namespace SSL_config
