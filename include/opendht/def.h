#pragma once

// Generic helper definitions for shared library support
#if defined _WIN32 || defined __CYGWIN__
  #define OPENDHT_IMPORT __declspec(dllimport)
  #define OPENDHT_EXPORT __declspec(dllexport)
  #define OPENDHT_HIDDEN
#else
  #define OPENDHT_IMPORT __attribute__ ((visibility ("default")))
  #define OPENDHT_EXPORT __attribute__ ((visibility ("default")))
  #define OPENDHT_HIDDEN __attribute__ ((visibility ("hidden")))
#endif

// Now we use the generic helper definitions above to define OPENDHT_PUBLIC and OPENDHT_LOCAL.
// OPENDHT_PUBLIC is used for the public API symbols. It either DLL imports or DLL exports (or does nothing for static build)
// OPENDHT_LOCAL is used for non-api symbols.

#ifdef opendht_EXPORTS // defined if OpenDHT is compiled as a shared library
  #ifdef OPENDHT_BUILD // defined if we are building the OpenDHT shared library (instead of using it)
    #define OPENDHT_PUBLIC OPENDHT_EXPORT
  #else
    #define OPENDHT_PUBLIC OPENDHT_IMPORT
  #endif // OPENDHT_BUILD
  #define OPENDHT_LOCAL OPENDHT_HIDDEN
#else // opendht_EXPORTS is not defined: this means OpenDHT is a static lib.
  #define OPENDHT_PUBLIC
  #define OPENDHT_LOCAL
#endif // opendht_EXPORTS


#ifdef opendht_c_EXPORTS // defined if OpenDHT is compiled as a shared library
  #ifdef OPENDHT_C_BUILD // defined if we are building the OpenDHT shared library (instead of using it)
    #define OPENDHT_C_PUBLIC OPENDHT_EXPORT
  #else
    #define OPENDHT_C_PUBLIC OPENDHT_IMPORT
  #endif // OPENDHT_BUILD
  #define OPENDHT_C_LOCAL OPENDHT_HIDDEN
#else // opendht_EXPORTS is not defined: this means OpenDHT is a static lib.
  #define OPENDHT_C_PUBLIC
  #define OPENDHT_C_LOCAL
#endif // opendht_EXPORTS

// bytes
#define HASH_LEN 20u
