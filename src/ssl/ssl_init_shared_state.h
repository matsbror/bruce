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
#include <openssl/err.h>
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
    static TSSL_Init& Instance(std::string clientCert){
      //  thread safe in C++11
      static TSSL_Init theInstance(clientCert);
      return theInstance;
    }

    SSL_CTX* get_ctx(){
      return ctx;
    }

    const std::string& getClientCertificate(){
      return clientCertificate;
    }

  private:

    

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
  TSSL_Init(std::string cc) :  clientCertificate{cc} {

      // remove when sure
      assert (!initialized);

      // Initalize basic SSL and BIO stuff

      SSL_library_init();
      SSL_load_error_strings();  
      ctx = InitCTX();

      if (SSL_CTX_use_certificate_chain_file(ctx, cc.c_str()) != 1){
	syslog(LOG_ERR, "Failed to load client side certificates from file: %s\n",
	       cc.c_str());

	while (unsigned long err = ERR_get_error()){
	  char errStr[120];
	  ERR_error_string(err, errStr);
	  std::cerr << "SSL error: " << err << ", " << errStr << std::endl;
	}

	throw std::runtime_error("Failed to load client side certificates from file " + 
				 cc);	
      }

      // assuming key is in the same file as the client certificate
      // This function might call for a passphrase
      if (SSL_CTX_use_PrivateKey_file(ctx, cc.c_str(), SSL_FILETYPE_PEM) != 1){
	syslog(LOG_ERR, "Failed to load client private key from file: %s\n", cc.c_str());
	throw std::runtime_error("Failed to load client private key from file: " + cc);	
      }

      // Load verified locations
      // not needed if server certificate is stored in /etc/ssl/certs

      // Search certificate chain 4 levels
      SSL_CTX_set_verify_depth(ctx, 4);

      nlocks = CRYPTO_num_locks();
      locks = new std::mutex[nlocks];
      if (locks){
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
      } else {
	syslog(LOG_ERR, "Failed to allocate memory for locks\n");
	throw std::runtime_error("Failed to allocate memory for locks");
      }

      initialized = true;

    } // TSSL_Init constructor

    //    TSSL_Init(TSSL_Init const&) = delete;

    ~TSSL_Init() {
      delete [] locks;
    }

    // Shared state
    SSL_CTX *ctx;              // SSL context
    std::string clientCertificate {};
    bool initialized {false};
    
  };  // class TSSL_Init



    
  } // namespace SSL_config
