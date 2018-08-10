#include <nan.h>
#include "BlowFish.h"

NAN_MODULE_INIT(InitModule) {
  BlowFish::Init(target);
}

NODE_MODULE(myModule, InitModule);