#include <stdexcept>

#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Returns (p, q, g) DH parameters. This function should:
 * 1) Initialize a `CryptoPP::AutoSeededRandomPool` object
 *    and a `CryptoPP::PrimeAndGenerator` object.
 * 2) Generate a prime p, sub-prime q, and generator g
 *    using `CryptoPP::PrimeAndGenerator::Generate(...)`
 *    with a `delta` of 1, a `pbits` of 512, and a `qbits` of 511.
 * 3) Store and return the parameters in a `DHParams_Message` object.
 * @note In practice, DH should have a prime p with 2048 bits and order q
 * with ~2047 bits. You are welcome to put these values into PrimeAndGenerator,
 * although you will notice that generating these primes frequently is very
 * expensive. Something optional to consider - how could you speed up this
 * process?
 * @return `DHParams_Message` object that stores Diffie-Hellman parameters
 */
DHParams_Message CryptoDriver::DH_generate_params() {
  // TODO: implement me!
  // initialize
  CryptoPP::AutoSeededRandomPool autoseed;
  CryptoPP::PrimeAndGenerator generator;
  CryptoPP::Integer p;
  CryptoPP::Integer q;
  CryptoPP::Integer g;
  // generate p, q, g
  generator.Generate(1, autoseed, 512, 511);
  p = generator.Prime();
  q = generator.SubPrime();
  g = generator.Generator();
  //store to message
  DHParams_Message dhmessage;
  dhmessage.p = p;
  dhmessage.q = q;
  dhmessage.g = g;

  return dhmessage;
}

/**
 * @brief Generate DH keypair. This function should
 * 1) Create a DH object and `SecByteBlock`s for the private and public keys.
 * Use `DH_obj.PrivateKeyLength()` and `PublicKeyLength()` to get key sizes.
 * 2) Generate a DH keypair using the `GenerateKeyPair(...)` method.
 * @param DH_params Diffie-Hellman parameters
 * @return Tuple containing DH object, private value, public value.
 */
std::tuple<DH, SecByteBlock, SecByteBlock>
CryptoDriver::DH_initialize(const DHParams_Message &DH_params) {
  // TODO: implement me!
  //create dh
  CryptoPP::Integer p = DH_params.p;
  CryptoPP::Integer q = DH_params.q;
  CryptoPP::Integer g = DH_params.g;

  DH dh(p, q, g);
  SecByteBlock privateKey(dh.PrivateKeyLength());
  SecByteBlock publicKey(dh.PublicKeyLength());
  CryptoPP::AutoSeededRandomPool autoseed;
  dh.GenerateKeyPair(autoseed, privateKey, publicKey);
  return std::make_tuple(dh, privateKey, publicKey);


}

/**
 * @brief Generates a shared secret. This function should
 * 1) Allocate space in a `SecByteBlock` of size `DH_obj.AgreedValueLength()`.
 * 2) Run `DH_obj.Agree(...)` to store the shared key in the allocated space.
 * 3) Throw an `std::runtime_error` if failed to agree.
 * @param DH_obj Diffie-Hellman object
 * @param DH_private_value user's private value for Diffie-Hellman
 * @param DH_other_public_value other user's public value for Diffie-Hellman
 * @return Diffie-Hellman shared key
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
    const DH &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {
  // TODO: implement me!
  // allocate space in secbyteblock
  SecByteBlock block(DH_obj.AgreedValueLength());
  //store share key and throw error
  if (DH_obj.Agree(block,DH_private_value,DH_other_public_value)){
    return block;
  }else{
    throw std::runtime_error("failed");
  }
}

/**
 * @brief Generates AES key using HKDF with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `AES::DEFAULT_KEYLENGTH`.
 * 2) Use an `HKDF<SHA256>` to derive and return a key for AES using the
 * provided salt. See the `DeriveKey` function. (Use NULL for the "info"
 * argument and 0 for "infolen".)
 * Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key Diffie-Hellman shared key
 * @return AES key
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key) {
  std::string aes_salt_str("salt0000");
  SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                        aes_salt_str.size());
  // TODO: implement me!
  //allocate
  SecByteBlock block(AES::DEFAULT_KEYLENGTH);
  //use hkdf<sha256>
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(block, block.size(), DH_shared_key, DH_shared_key.size(), aes_salt, aes_salt.size(),NULL, 0);
  return block;
}

/**
 * @brief Encrypts the given plaintext. This function should:
 * 1) Initialize `CBC_Mode<AES>::Encryption` using GetNextIV and SetKeyWithIV.
 * 1.5) IV should be of size `AES::BLOCKSIZE`
 * 2) Run the plaintext through a `StreamTransformationFilter` using
 * the AES encryptor.
 * 3) Return ciphertext and iv used in encryption or throw an
 * `std::runtime_error`.
 * Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param plaintext text to encrypt
 * @return Pair of ciphertext and iv
 */
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext) {
  try {
    // TODO: implement me!
    //initialize
    CBC_Mode<AES>::Encryption encrypt;
    SecByteBlock iv(AES::BLOCKSIZE);
    CryptoPP::AutoSeededRandomPool rng;
    encrypt.GetNextIV(rng, iv);
    encrypt.SetKeyWithIV(key, key.size(), iv);
    //use aes encryptor
    std::string cipher;
    StringSource s(plaintext, true, 
            new StreamTransformationFilter(encrypt,
                new StringSink(cipher)
            ) 
        ); 
    return std::make_pair(cipher, iv);
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext, encoded as a hex string. This function
 * should:
 * 1) Initialize `CBC_Mode<AES>::Decryption` using `SetKeyWithIV` on the 
 * key and iv. 
 * 2) Run the decoded ciphertext through a `StreamTransformationFilter`
 * using the AES decryptor.
 * 3) Return the plaintext or throw an `std::runtime_error`.
 * Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param iv iv used in encryption
 * @param ciphertext text to decrypt
 * @return decrypted message
 */
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext) {
  try {
    // TODO: implement me!
    //initialize the decryptor
    CBC_Mode<AES>::Decryption decrypt;
    decrypt.SetKeyWithIV(key, key.size(), iv);
    //run decoded 
    std::string plaintext;
    StringSource s(ciphertext, true, 
            new StreamTransformationFilter(decrypt,
                new StringSink(plaintext)
            ) 
        ); 
    return plaintext;
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `SHA256::BLOCKSIZE` for the shared key.
 * 2) Use an `HKDF<SHA256>` to derive and return a key for HMAC using the
 * provided salt. See the `DeriveKey` function.
 * Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key shared key from Diffie-Hellman
 * @return HMAC key
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key) {
  std::string hmac_salt_str("salt0001");
  SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                         hmac_salt_str.size());
  // TODO: implement me!
  SecByteBlock block(SHA256::BLOCKSIZE);
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(block, block.size(), DH_shared_key, DH_shared_key.size(), hmac_salt, hmac_salt.size(),NULL, 0);
  return block;
}

/**
 * @brief Given a ciphertext, generates an HMAC. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the ciphertext through a `HashFilter` to generate an HMAC.
 * 3) Throw `std::runtime_error` upon failure.
 * @param key HMAC key
 * @param ciphertext message to tag
 * @return HMAC (Hashed Message Authentication Code)
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {
    // TODO: implement me!
    std::string mac;
    HMAC< SHA256 > hmac(key, key.size());
    StringSource ss2(ciphertext, true, new HashFilter(hmac,new StringSink(mac)));
    return mac;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks if the MAC is valid. This function
 * should 
 * 1) Initialize an `HMAC<SHA256>` with the provided key. 
 * 2) Run the message through a `HashVerificationFilter` to verify the HMAC. 
 * 3) Return false upon failure.
 * @param key HMAC key
 * @param ciphertext message to verify
 * @param mac associated MAC
 * @return true if MAC is valid, else false
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  const int flags = HashVerificationFilter::THROW_EXCEPTION |
                    HashVerificationFilter::HASH_AT_END;
  try {
    // TODO: implement me!
    HMAC< SHA256 > hmac(key, key.size());
    StringSource(ciphertext + mac, true, 
        new HashVerificationFilter(hmac, NULL, flags)
    );
    return true;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    return false;
  }
}

/**
 *use HKDF to generate root key
 */
std::pair<SecByteBlock, SecByteBlock> CryptoDriver::generateRootKey(SecByteBlock rootkey, SecByteBlock DH_output){
  HKDF<SHA256> hkdf;
  SecByteBlock res(64);
  hkdf.DeriveKey(res, 64, DH_output, DH_output.size(), rootkey, rootkey.size(), nullptr, 0);
  SecByteBlock newrootkey(res, 32);
  SecByteBlock newchainkey(res+32, 32);
  return {newrootkey, newchainkey};
}

/**
 * use hmac to get currentkey and chainkey for next cycle
 */
std::pair<SecByteBlock, SecByteBlock>CryptoDriver::generateChainKey(SecByteBlock chainKey){
  SecByteBlock currentkey(SHA256::DIGESTSIZE);
  SecByteBlock newchainkey (SHA256::DIGESTSIZE);
  
  byte b1 = 0x01;
  HMAC<SHA256> hmac1(chainKey, chainKey.size());
  hmac1.Update(&b1, 1);
  hmac1.Final(currentkey.BytePtr());

  byte b2 = 0x02;
  HMAC<SHA256> hmac2(chainKey, chainKey.size());
  hmac2.Update(&b2, 1);
  hmac2.Final(newchainkey.BytePtr());

  return {currentkey, newchainkey};
  
}
