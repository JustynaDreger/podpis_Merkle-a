//podpis dokumentu za pomocą schematu podpisu jednorazowego Lamporta-Diffiego

#include <iostream>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;
//wypisanie błędu
void error()
{
  ERR_print_errors_fp(stderr);
  abort();
}
//tworzenie skrótu wiadomości
void d_M(char *M, unsigned char **d, unsigned int *d_len)
{
  size_t M_len = strlen(M);
  //tworzenie kontekstu skrótu
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if(ctx == NULL)
    error();
  //ustawienie typu skrótu i implementacji (domyślna)
	if(1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
    error();
  //przekazania M_len bajtów z M do kontekstu skrótu
	if(EVP_DigestUpdate(ctx, M, M_len) != 1)
		error();
//allokacja pamięci dla skrótu o rozmarze odpowiedniego typu
  *d = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
  if(d == NULL)
    error();
//zapis d_len bajtów skrótu z kontekstu ctx do d
	if(EVP_DigestFinal_ex(ctx, *d, d_len) != 1)
		error();
//czyszczenie kontekstu i zwalnianie pamięci
	EVP_MD_CTX_free(ctx);
}
int main(int argc, char *argv[]){

  if(argc==1)
  {
    cout<<"Nie podano wiadomości do podpisania!"<<endl;
    return -1;
  }
  cout<<"Wiadomość do podpisu: "<<argv[1]<<endl;

  //obliczenie skrotu wiadomosci - g(M)_
  char *M=argv[1];
  unsigned char **d;
  unsigned int *d_len;
  d_M(M,d,d_len);

  cout<<"Skrót wiadomości: "<<endl<<*d<<endl;

  return 0;
}
