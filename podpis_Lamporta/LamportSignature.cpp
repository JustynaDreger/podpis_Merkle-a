#include "LamportSignature.h"

LamportSignature::LamportSignature()
{
  string M;
  cout<<"Podaj wiadomosc :"<<endl;
  cin>>M;
  d_M(M);
}
void LamportSignature::d_M(string m)
{
  cout<<"Oblicznie skrotu"<<endl;
  const char *M = m.c_str();
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if(ctx == NULL)
    error();
  if(EVP_DigestInit_ex(ctx,EVP_sha256(),NULL) != 1)
    error();
  if(EVP_DigestUpdate(ctx,M,sizeof(M)) != 1)
    error();
  unsigned int *d_len = NULL;
  *d = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
  if(*d == NULL)
    error();
  if(EVP_DigestFinal_ex(ctx,*d,d_len) != 1)
    error();
  EVP_MD_CTX_free(ctx);
  cout<<"Skrot :"<<endl<<*d<<endl;
}
void LamportSignature::error(){
  ERR_print_errors_fp(stderr);
  abort();
}
