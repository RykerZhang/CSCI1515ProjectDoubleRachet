#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param network_driver NetworkDriver to handle network operations i.e. sending and receiving msgs 
 * @param crypto_driver CryptoDriver to handle crypto related functionality
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call `DH_generate_shared_key`
 * 2) Use the resulting key in `AES_generate_key` and `HMAC_generate_key`
 * 3) Update private key variables
 */
void Client::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value) {
  // TODO: implement me!
  //call dh
  SecByteBlock block = this->crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);
  //use key in aes and hmac
  this->AES_key = this->crypto_driver->AES_generate_key(block);
  this->HMAC_key = this->crypto_driver->HMAC_generate_key(block);
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
Message_Message Client::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  // TODO: implement me!
  //check if dh need to change
  CryptoPP:: SecByteBlock prv;
  CryptoPP:: SecByteBlock pub;
  if(this->DH_switched){
    //UPDATE
    std::tuple<DH, SecByteBlock, SecByteBlock> result = this->crypto_driver->DH_initialize(this->DH_params);
    CryptoPP::DH dh = std::get<0>(result);
    prv = std::get<1>(result);
    pub = std::get<2>(result);
    // DH ratchet derive new rootkey and sentchainkey
    SecByteBlock dh_out = this->crypto_driver->DH_generate_shared_key(dh, prv, this->DH_last_other_public_value);
    auto [new_rk, new_ck] = this->crypto_driver->generateRootKey(this->rootkey, dh_out);
    this->rootkey = new_rk;
    this->previouscount = this->sentmessagecount;
    this->sentchainkey = new_ck;
    this->sentmessagecount = 0;
    this->DH_switched = false;
    this->DH_current_public_value = pub;
    this->DH_current_private_value = prv;
  }
  // send chain, get message key
  auto [currentkey, nextsentchainkey] = this->crypto_driver->generateChainKey(this->sentchainkey);
  this->sentchainkey = nextsentchainkey;

  // derive AES and HMAC keys from message key
  SecByteBlock aeskey = this->crypto_driver->AES_generate_key(currentkey);
  SecByteBlock hmackey = this->crypto_driver->HMAC_generate_key(currentkey);

  // encrypt and tag
  std::pair<std::string, SecByteBlock> encryptresult = this->crypto_driver->AES_encrypt(aeskey, plaintext);
  std::string ciphertext = encryptresult.first;
  SecByteBlock iv = encryptresult.second;
  Message_Message msg;
  msg.ciphertext = ciphertext;
  msg.iv = iv;
  msg.public_value = this->DH_current_public_value;
  std::string input = std::string(iv.begin(), iv.end()) + ciphertext;
  msg.mac = this->crypto_driver->HMAC_generate(hmackey, input);
  msg.messageIndex = this->sentmessagecount++;
  msg.previousMessageIndex = this->previouscount;
  return msg;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> Client::receive(Message_Message msg) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  // TODO: implement me!
  // //check if the ratchet is changed
  // if (this->DH_last_other_public_value != msg.public_value){
  //   //not equal, update it
  //   //alter the switch signal
  //   this->DH_switched = true;
  //   //use new key
  //   std::tuple<DH, SecByteBlock, SecByteBlock> result = this->crypto_driver->DH_initialize(this->DH_params);
  //   CryptoPP::DH dh = std::get<0>(result);
  //   CryptoPP:: SecByteBlock prv = std::get<1>(result);
  //   CryptoPP:: SecByteBlock pub = std::get<2>(result);
  //   this->prepare_keys(dh, this->DH_current_private_value, msg.public_value);
  //   this->DH_last_other_public_value = msg.public_value;
  // }
  //  //mac concatenation
  //   std::string temp = std::string(msg.iv.begin(), msg.iv.end());
  //   std::string input = temp+msg.ciphertext;
  //   //verify
  //   bool verification = this->crypto_driver->HMAC_verify(this->HMAC_key, input, msg.mac);
  //   std::string decryptresult = "";
  //   if(verification){ 
  //     //decrypt
  //    decryptresult = this->crypto_driver->AES_decrypt(this->AES_key, msg.iv, msg.ciphertext);
  //   }
  //   return std::make_pair(decryptresult, verification);

  // check skipped message key cache
  std::string pub_key_str = byteblock_to_string(msg.public_value);
  auto skipped_it = this->skippedmessagekey.find({pub_key_str, msg.messageIndex});

  if (skipped_it != this->skippedmessagekey.end()) {
    SecByteBlock currentkey = skipped_it->second;
    this->skippedmessagekey.erase(skipped_it);
    SecByteBlock aeskey = this->crypto_driver->AES_generate_key(currentkey);
    SecByteBlock hmackey = this->crypto_driver->HMAC_generate_key(currentkey);
    std::string input = std::string(msg.iv.begin(), msg.iv.end()) + msg.ciphertext;
    bool ok = this->crypto_driver->HMAC_verify(hmackey, input, msg.mac);
    if (!ok) return {"", false};
    return {this->crypto_driver->AES_decrypt(aeskey, msg.iv, msg.ciphertext), true};
  }

  // DH ratchet if peer used a new public key
  std::string last_pub_str = byteblock_to_string(this->DH_last_other_public_value);
  if (pub_key_str != last_pub_str) {
    // cache skipped keys from old receiving chain up to previousMessageIndex
    while (this->receivedmessagecount < msg.previousMessageIndex) {
      auto p = this->crypto_driver->generateChainKey(this->receivechainkey);
      this->skippedmessagekey[{last_pub_str, this->receivedmessagecount}] = p.first;
      this->receivechainkey = p.second;
      this->receivedmessagecount++;
    }
    // DH ratchet: update rootkey and receivechainkey
    CryptoPP::DH dh(this->DH_params.p, this->DH_params.q, this->DH_params.g);
    SecByteBlock dh_out = this->crypto_driver->DH_generate_shared_key(
        dh, this->DH_current_private_value, msg.public_value);
    auto root_p = this->crypto_driver->generateRootKey(this->rootkey, dh_out);
    this->rootkey = root_p.first;
    this->receivechainkey = root_p.second;
    this->DH_last_other_public_value = msg.public_value;
    this->receivedmessagecount = 0;
    this->DH_switched = true;
  }

  // cache any skipped keys in current receiving chain
  while (this->receivedmessagecount < msg.messageIndex) {
    auto p = this->crypto_driver->generateChainKey(this->receivechainkey);
    this->skippedmessagekey[{pub_key_str, this->receivedmessagecount}] = p.first;
    this->receivechainkey = p.second;
    this->receivedmessagecount++;
  }

  // get current message key and decrypt
  auto final_p = this->crypto_driver->generateChainKey(this->receivechainkey);
  SecByteBlock currentkey = final_p.first;
  this->receivechainkey = final_p.second;
  this->receivedmessagecount++;

  SecByteBlock aeskey = this->crypto_driver->AES_generate_key(currentkey);
  SecByteBlock hmackey = this->crypto_driver->HMAC_generate_key(currentkey);
  std::string input = std::string(msg.iv.begin(), msg.iv.end()) + msg.ciphertext;
  bool ok = this->crypto_driver->HMAC_verify(hmackey, input, msg.mac);
  if (!ok) return {"", false};
  return {this->crypto_driver->AES_decrypt(aeskey, msg.iv, msg.ciphertext), true};
}

/**
 * Run the client.
 */
void Client::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();

  // Run key exchange.
  this->HandleKeyExchange(command);

  // Start msgListener thread.
  boost::thread msgListener =
      boost::thread(boost::bind(&Client::ReceiveThread, this));
  msgListener.detach();

  // Start sending thread.
  this->SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send DHParams_Message depending on `command`.
 * `command` can be either "listen" or "connect"; the listener should `read()`
 * for params, and the connector should generate and send params.
 * 2) Initialize DH object and keys
 * 3) Send your public value
 * 4) Listen for the other party's public value
 * 5) Generate DH, AES, and HMAC keys and set local variables
 */
void Client::HandleKeyExchange(std::string command) {
  // TODO: implement me! 。。。/
  DHParams_Message msg;
  if (command == "listen"){
    //read for params
    std::vector<unsigned char> readresult = this->network_driver->read();
    msg.deserialize(readresult);
  }else if(command == "connect"){
    //generate and send params
    std::vector<unsigned char> sendcontent;
    msg = this->crypto_driver->DH_generate_params();
    msg.serialize(sendcontent);
    this->network_driver->send(sendcontent);
  }
  this->DH_params = msg;
  //intialize dh and keys
  std::tuple<CryptoPP::DH, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> result = this->crypto_driver->DH_initialize(msg);
  CryptoPP::DH dh = std::get<0>(result);
  SecByteBlock prv = std::get<1>(result);
  SecByteBlock pub = std::get<2>(result);

  //send the public value
  PublicValue_Message publicmsg1;
  std::vector<unsigned char> sendval;
  publicmsg1.public_value = pub;
  publicmsg1.serialize(sendval);
  this->DH_current_private_value = prv;
  this->DH_current_public_value = pub;
  this->network_driver->send(sendval);

  //listen to others public val
  std::vector<unsigned char> receivemsg = this->network_driver->read();
  PublicValue_Message othermsg1;
  othermsg1.deserialize(receivemsg);

  //generate dh, aes, hmac
  this->DH_last_other_public_value = othermsg1.public_value;
  this->prepare_keys(dh, prv, othermsg1.public_value);

  //initialize root key and chain key from initial dh shared key
  SecByteBlock initialshared = this->crypto_driver->DH_generate_shared_key(dh, prv, othermsg1.public_value);
  auto [newrootkey, newchainkey] = this->crypto_driver->generateRootKey(initialshared, initialshared);
  this->rootkey = newrootkey;

  if (command == "connect"){
    this->sentchainkey = newchainkey;
    this->DH_switched = false;
  }else{
    this->receivechainkey = newchainkey;
    this->DH_switched = true;
  }
  this->sentmessagecount = 0;
  this->receivedmessagecount = 0;
  this->previouscount = 0;
}

/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try {
      data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message msg;
    msg.deserialize(data);
    auto decrypted_data = this->receive(msg);
    if (!decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    this->cli_driver->print_left(std::get<0>(decrypted_data));
  }
}

/**
 * Listen for stdin and send to other party.
 */
void Client::SendThread() {
  std::string plaintext;
  while (true) {
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      Message_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data);
    }
    this->cli_driver->print_right(plaintext);
  }
}