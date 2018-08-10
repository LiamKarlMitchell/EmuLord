#include <nan.h>

#ifndef uint32_t
typedef unsigned __int32 uint32_t;
#endif

class BlowFish : public Nan::ObjectWrap {
public:

  uint32_t P[18];				 /*!<  Blowfish round keys    */
  uint32_t S[4][256];            /*!<  key dependent S-boxes  */

  static NAN_MODULE_INIT(Init);
  static NAN_METHOD(New);

  static NAN_METHOD(SetKey);
  // Note: The purpose of Decrypt and Encrypt is to process an entire buffer.
  static NAN_METHOD(Decrypt);
  static NAN_METHOD(Encrypt);

  static NAN_GETTER(HandleGetters);
  static NAN_SETTER(HandleSetters);

  static Nan::Persistent<v8::FunctionTemplate> constructor;


  // TODO: Decide if need to inline encrypt and decrypt?
  void BlowFish::init();
  void free();
  void decrypt(uint32_t * xl, uint32_t * xr);
  void encrypt(uint32_t * xl, uint32_t * xr);
  int setKey(const unsigned char *key, unsigned int keybits);

};


