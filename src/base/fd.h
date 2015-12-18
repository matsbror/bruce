/* <base/fd.h>

   ----------------------------------------------------------------------------
   Copyright 2010-2013 if(we)
             2015 OLA Mobile

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

   An RAII container for an OS file descriptor.

   Added methods for the operations in io_utils in order to be able
   to make this container an abstract container.
 */

#pragma once

#include <algorithm>
#include <cassert>

#include <unistd.h>
#include <sys/socket.h>

#include <base/error_utils.h>
#include <base/no_copy_semantics.h>

namespace Base {

  /* An RAII container for an OS file descriptor.

     This is a value type.  If you copy an instance of this class, it will use
     dup() to copy the file descriptor it contains (if any).

     This class implicitly casts to int, so you can use an instance of it in
     any call where you would normally pass a naked file descriptor.

     You can construct an instance of this class to capture the result of a
     function, such as the OS function socket(), which returns a newly created
     file descriptor.

     For example:

        TFd sock(HERE, socket(IF_INET, SOCK_STREAM, IPPROTO_TCP));

     If socket() fails (and so returns a negative value), the TFd constructor
     will throw an instance of std::system_error.

     You may also pass a naked file descriptor in the stdio range (0-2) to this
     constructor.  In this case, the newly constructed object will hold the
     file desciptor, but it will not attempt to close it. */
  class TFd {
    public:

    /* Default-construct as an illegal value (-1). */
    TFd() noexcept
        : OsHandle(-1) {
    }

    /* Move-construct, leaving the donor in the default-constructed state. */
    TFd(TFd &&that) noexcept {
      assert(&that);
      OsHandle = that.OsHandle;
      that.OsHandle = -1;
    }

    /* Copy-construct, duplicating the file descriptor with the OS call dup(),
       if necessary. */
    TFd(const TFd &that) {
      assert(&that);
      OsHandle = (that.OsHandle >= 3) ?
          IfLt0(dup(that.OsHandle)) : that.OsHandle;
    }

    /* Construct from a naked file descriptor, which the new instance will own.
       Use this constructor to capture the result of an OS function, such as
       socket(), which returns a newly created file descriptor.  If the result
       is not a legal file descriptor, this function will throw the appropriate
       error. */
    TFd(int os_handle) {
      OsHandle = IfLt0(os_handle);
    }

    /* Close the file descriptor we own, if any.  If the descriptor is in the
       stdio range (0-2), then don't close it. */
    ~TFd() noexcept {
      assert(this);

      if (OsHandle >= 3) {
        close(OsHandle);
      }
    }

    /* Swaperator. */
    TFd &operator=(TFd &&that) noexcept {
      assert(this);
      assert(&that);
      std::swap(OsHandle, that.OsHandle);
      return *this;
    }

    /* Assignment.  This will duplicate the file descriptor, if any, using the
       OS function dup(). */
    TFd &operator=(const TFd &that) {
      assert(this);
      return *this = TFd(that);
    }

    /* Assign from a naked file descriptor, which we will now own.  Use this
       constructor to capture the result of an OS function, such as socket(),
       which returns a newly created file descriptor.  If the result is not a
       legal file descriptor, this function will throw the appropriate
       error. */
    TFd &operator=(int os_handle) {
      assert(this);
      return *this = TFd(os_handle);
    }

    /* Returns the naked file descriptor, which may be -1. */
    operator int() const noexcept {
      assert(this);
      return OsHandle;
    }

    /* True iff. this handle is open. */
    bool IsOpen() const noexcept {
      assert(this);
      return OsHandle >= 0;
    }

    /* True iff. the file descriptor can be read from without blocking.
       Waits for at most the given number of milliseconds for the descriptor to
       become readable.  A negative timeout will wait forever. */
    bool IsReadable(int timeout = 0) const;

    /* Returns the naked file desciptor, which may be -1, and returns to the
       default-constructed state.  This is how to get the naked file desciptor
       away from the object without the object attempting to close it. */
    int Release() noexcept {
      assert(this);
      int result = OsHandle;
      OsHandle = -1;
      return result;
    }

    /* Return to the default-constructed state. */
    TFd &Reset() noexcept {
      assert(this);
      return *this = TFd();
    }

    /* Construct the read- and write-only ends of a pipe. */
    static void Pipe(TFd &readable, TFd &writeable, int flags = 0) {
      assert(&readable);
      assert(&writeable);
      int fds[2];
      IfLt0(pipe2(fds, flags) < 0);
      readable = TFd(fds[0], NoThrow);
      writeable = TFd(fds[1], NoThrow);
    }

    /* Construct both ends of a socket. */
    static void SocketPair(TFd &lhs, TFd &rhs, int domain, int type,
        int proto = 0) {
      assert(&lhs);
      assert(&rhs);
      int fds[2];
      IfLt0(socketpair(domain, type, proto, fds));
      lhs = TFd(fds[0], NoThrow);
      rhs = TFd(fds[1], NoThrow);
    }



    /* The 'AtMost' versions of read and write are basically just wrappers around
       the OS functions.  They will transfer as much data as possible, up to the
       given max, and return the number of bytes they tranferred.  They will
       raise std::system_error if anything goes wrong or if they are interrupted.
    */
    
    /* Read at most 'max_size' bytes into 'buf', throwing appropriately. */
    size_t ReadAtMost(void *buf, size_t max_size);
    
    /* Same as above, but with timeout in milliseconds.  Throws std::system_error
       with code of ETIMEDOUT on timeout.  A negative timeout value means
       "infinite timeout". */
    size_t ReadAtMost(void *buf, size_t max_size, int timeout_ms);
    
    /* Write at most 'max_size' bytes from 'buf', throwing appropriately.
       If the fd is a socket, we will do this operation with send() instead of
       write(), to suppress SIGPIPE. */
    size_t WriteAtMost(const void *buf, size_t max_size);
    
    /* Same as above, but with timeout in milliseconds.  Throws std::system_error
       with code of ETIMEDOUT on timeout.  A negative timeout value means
       "infinite timeout". */
    size_t WriteAtMost(const void *buf, size_t max_size, int timeout_ms);

    /* The 'TryExactly' versions of read and write will call the OS functions
       repeatedly until the full number of bytes is transferred.  If the first OS
       call results in zero bytes being transferred (indicating, for example, the
       the other end of the pipe is closed), the function will stop trying to
       transfer and return false.  If any subseqeuent transfer returns zero
       bytes, the function will throw a std::runtime_error indicating that the
       transfer ended unexpectedly.  If the full number of bytes are tranferred
       successfully, the function returns true. */
    
    /* An instance of this class is thrown by the 'TryExactly' functions when a
       transfer was started successfully but could not finish. */
    class TUnexpectedEnd : public std::runtime_error {
    public:
      /* Do-little. */
    TUnexpectedEnd()
      : std::runtime_error("unexpected end") {
      }
    };  // TUnexpectedEnd
    
    /* Try to read exactly 'size' bytes into 'buf'.
       Retry until we get enough bytes, then return true.
       If we get a zero-length return, return false.
       Throw appropriately. */
    bool TryReadExactly(void *buf, size_t size);

    /* Same as above, but with timeout in milliseconds.  Throws std::system_error
       with code of ETIMEDOUT if entire read is not completed within the timeout
       period.  A negative timeout value means "infinite timeout". */
    bool TryReadExactly(void *buf, size_t size, int timeout_ms);
    
    /* Try to write exactly 'size' bytes from 'buf'.
       Retry until we put enough bytes, then return true.
       If we get a zero-length return, return false.
       Throw appropriately. */
    bool TryWriteExactly(const void *buf, size_t size);
    
    /* Same as above, but with timeout in milliseconds.  Throws std::system_error
       with code of ETIMEDOUT if entire write is not completed within the timeout
       period.  A negative timeout value means "infinite timeout". */
    bool TryWriteExactly(const void *buf, size_t size, int timeout_ms);

    /* The 'Exactly' versions of read and write work like the 'TryExactly'
       versions (see above), except that they do not tolerate a failure to start.
       If the transfer could start, they a throw std::runtime_error indicating
       so. */
    
    /* An instance of this class is thrown by the 'Exactly' functions when a
       transfer could not start. */
    class TCouldNotStart : public std::runtime_error {
    public:
      /* Do-little. */
    TCouldNotStart()
      : std::runtime_error("could not start") {
      }
    };  // TCouldNotStart
    
    /* Read exactly 'size' bytes into 'buf', throwing appropriately. */
    inline void ReadExactly(void *buf, size_t size) {
      if (!TryReadExactly(buf, size)) {
	throw TCouldNotStart();
      }
    }
    
    /* Same as above, but with timeout in milliseconds.  Throws std::system_error
       with code of ETIMEDOUT if entire read is not completed within the timeout
       period.  A negative timeout value means "infinite timeout". */
    inline void ReadExactly(void *buf, size_t size, int timeout_ms) {
      if (!TryReadExactly(buf, size, timeout_ms)) {
	throw TCouldNotStart();
      }
    }

    /* Write exactly 'size' bytes into 'buf', throwing appropriately. */
    inline void WriteExactly(const void *buf, size_t size) {
      if (!TryWriteExactly(buf, size)) {
	throw TCouldNotStart();
      }
    }
    
    /* Same as above, but with timeout in milliseconds.  Throws std::system_error
       with code of ETIMEDOUT if entire write is not completed within the timeout
       period.  A negative timeout value means "infinite timeout". */
    inline void WriteExactly(const void *buf, size_t size,
			     int timeout_ms) {
      if (!TryWriteExactly(buf, size, timeout_ms)) {
	throw TCouldNotStart();
      }
    }

    /* Sets the given fd to close-on-exec. */
    void SetCloseOnExec();
    
    /* Sets the given fd to non-blocking I/O. */
    void SetNonBlocking();


    private:
    /* Use to disambiguate construction for Pipe() and SocketPair(). */
    enum TNoThrow { NoThrow };

    /* Constuctor used by Pipe() and SocketPair(). */
    TFd(int os_handle, TNoThrow) noexcept
        : OsHandle(os_handle) {}

    /* The naked file descriptor we wrap.  This can be -1. */
    int OsHandle;
  };  // TFd

  /* Wrappers of stdin (0), stdout (1), and stderr (2). */
  extern const TFd In, Out, Err;

}  // Base
