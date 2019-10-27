#include <iostream>
#include <cstring>
#include <string>
#include <iomanip>
#include <bitset>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstdio>

using namespace std;
#define N 32
#define N2 N*16
class LamportSignature
{
  unsigned char d[N];
  unsigned char X[N2][N];
  unsigned char Y[N2][N];
  unsigned char **s;
  unsigned int d_len;
  unsigned int y_len;
  void d_M(string M);
  void error();
  void keyXGenerate();
  void keyYGenerate();
  public:
    LamportSignature();
    void keyGenerate();
    void signatureGenerate();
    void signatureVerifite();
    void showKeyX();
    void showKeyY();
    void showSignature();
    void showDigest();
};
