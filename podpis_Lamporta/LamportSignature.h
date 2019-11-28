#include <iostream>
#include <cstring>
#include <string>
#include <algorithm>
#include <iomanip>
#include <bitset>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <ejdb2/ejdb2.h>

using namespace std;
#define N 32
#define N2 N*16
#define RCHECK(rc_)          \
  if (rc_) {                 \
    iwlog_ecode_error3(rc_); \
    return 1;                \
  }
static int globalId;
class LamportSignature
{
  unsigned char *d;// dlugosc N
  unsigned char X[N2][N];
  unsigned char Y[N2][N];
  unsigned char s[N*8][N];
  unsigned int d_len;
  unsigned int y_len;

  void d_M(string M);
  void error();
  void keyXGenerate();
  void keyYGenerate();
  string convertKeyToString();
  void convertKeyToUchar(string sKey);
  void saveSignatureIntoFile();
  void saveIntoDataBase();
  void readSignatureFromFile(string fileName);
  void readFromDataBase();
  string readMessageFromFile(string fileName);
  static iwrc documents_visitor(EJDB_EXEC *ctx, const EJDB_DOC doc, int64_t *step);
  static iwrc documents_visitor2(EJDB_EXEC *ctx, const EJDB_DOC doc, int64_t *step);
  public:
    LamportSignature(string messageFileName); // tworzenie podpisu
    LamportSignature(string messageFileName,string signatureFile); //weryfikacja podpisu
    void keyGenerate();
    void signatureGenerate();
    void signatureVerify(string fileName);
    void showKeyX();
    void showKeyY();
    void showSignature();
    void showDigest();
    ~LamportSignature();
};
