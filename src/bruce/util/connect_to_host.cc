/* <bruce/util/connect_to_host.cc>

   ----------------------------------------------------------------------------
   Copyright 2013-2014 if(we)

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

   Implements <bruce/util/connect_to_host.h>.
 */

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <iostream>
#include <iomanip>

#include <base/error_utils.h>
#include <bruce/util/connect_to_host.h>
#include <socket/db/cursor.h>

using namespace Base;
using namespace SSL_config;
using namespace Socket;


void Bruce::Util::ConnectToHost(const char *host_name, in_port_t port,
    TFd &result_socket) {
  assert(host_name);
  result_socket.Reset();

  /* Iterate over our potential hosts. */
  for (Db::TCursor csr(host_name, nullptr, AF_INET, SOCK_STREAM, 0,
                       AI_PASSIVE);
       csr;
       ++csr) {
    /* Get the address of the host we're going to try and set the port. */
    TAddress address = *csr;
    address.SetPort(port);

    /* Create a socket that's compatible with candidate host. */
    TFd sock = csr.NewCompatSocket();

    if (!connect(sock, address, address.GetLen())) {
      result_socket = std::move(sock);
      break;  // success
    }

    /* What went wrong? */
    switch (errno) {
      case ECONNREFUSED:
      case ETIMEDOUT:
      case EHOSTUNREACH:
      case EHOSTDOWN: {
        /* These errors aren't serious.  Move on to the next host. */
        break;
      }
      default: {
        /* Anything else is big-time serious. */
        ThrowSystemError(errno);
      }
    }
  }
} // TFd ConnectToHost



// This connection might need to negotiate an SSL connection
//
void Bruce::Util::ConnectToHost(const char *host_name, in_port_t port,
				TAbstractSocket &result_socket, bool UseSsl) {
  assert(host_name);
  result_socket.Reset();

  /* Iterate over our potential hosts. */
  for (Db::TCursor csr(host_name, nullptr, AF_INET, SOCK_STREAM, 0,
                       AI_PASSIVE);
       csr;
       ++csr) {
    /* Get the address of the host we're going to try and set the port. */
    TAddress address = *csr;
    address.SetPort(port);

    /* Create a socket that's compatible with candidate host. */
    TAbstractSocket sock = csr.NewAbstractSocket(UseSsl);

    // set non blocking is with SSL
    if (UseSsl) {
      //      sock.SetNonBlocking();
    }

    if (!connect(sock, address, address.GetLen())) {
      result_socket = std::move(sock);
      break;  // success, break out of for loop
    }


    /* What went wrong? */
    switch (errno) {
      case ECONNREFUSED:
      case ETIMEDOUT:
      case EHOSTUNREACH:
      case EHOSTDOWN: {
        /* These errors aren't serious.  Move on to the next host. */
        break;
      }
      default: {
        /* Anything else is big-time serious. */
        ThrowSystemError(errno);
      }
    } // switch    
  } // for
  
    // If SSL is used, try to make the connection
  if (UseSsl) {
    // try to connect SSL to server
    std::cout << "Trying to connect to SSL server..." << std::endl;
    int ret = SSL_connect(result_socket.getSSL());
    int thisError = errno;
    std::cout << "SSL_connect returned: " << ret << std::endl;
    if (ret <= 0){
      int ssl_err { SSL_get_error(result_socket.getSSL(), ret)};
      std::cout << "SSL_connect error: " << ssl_err << ", errno: " << thisError <<std::endl;
      syslog(LOG_ERR, "SSL_connect error: %d\n", ssl_err);

      unsigned long errcode = ERR_get_error();
      while (errcode){
	std::cout << "SSL error code: " << std::hex << errcode << std::endl;
	errcode = ERR_get_error();
      }

      throw std::runtime_error("SSL Connec error: " + 
			       std::to_string(ssl_err));
    }
    
    // show certs and other information, for debug only
    std::cout << "[" << SSL_get_version(result_socket.getSSL()) << ", " <<
      SSL_get_cipher(result_socket.getSSL()) << "]\n";
    
    result_socket.ShowCerts();        /* show any certs */
    
    std::cerr << "Connection opened on client..." << std::endl;
  } // if (UseSsl)

} // TAbstractSocket ConnectToHost
