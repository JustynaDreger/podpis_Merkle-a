#include <iostream>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
using namespace std;
class LamportSignature
{
  unsigned char **d;
  void d_M(string M);
  void error();
  public:
    LamportSignature();
    void keyGenerate();
};
