#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"

#include <crypto++/nbtheory.h>
#include "../include-shared/util.hpp"
#include "../include-shared/messages.hpp"
#include "../include/drivers/crypto_driver.hpp"
// include more header files if needed for any tests you add to this file
// (you might need to include network_driver.hpp, client.hpp etc)

TEST_CASE("sample") { CHECK(true); }

TEST_CASE("sanity-dh-initialization") {
  std::cout << "TESTING: sanity-dh-initialization" << std::endl;

  CryptoDriver crypto_driver;
  DHParams_Message params = crypto_driver.DH_generate_params();
  auto keys = crypto_driver.DH_initialize(params);

  // Check that the public value g^a is indeed g raised to the private value a
  CHECK(ModularExponentiation(params.g, byteblock_to_integer(std::get<1>(keys)),
                              params.p) ==
        byteblock_to_integer(std::get<2>(keys)));
}