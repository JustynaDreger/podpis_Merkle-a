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
  cout<<"Obliczanie skrotu"<<endl;
  char M[m.size()+1];
  strcpy(M,m.c_str());

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if(ctx == NULL)
    error();
  if(EVP_DigestInit_ex(ctx,EVP_sha256(),NULL) != 1)
    error();
  if(EVP_DigestUpdate(ctx,M,strlen(M)) != 1)
    error();
  if(EVP_DigestFinal_ex(ctx,d,&d_len) != 1)
    error();
  EVP_MD_CTX_free(ctx);
  cout<<"Skrot :"<<endl;
  for (int i = 0; i < N; i++)
      printf("%02x", d[i]);
  cout<<endl<<d_len<<endl;
}
void LamportSignature::error(){
  ERR_print_errors_fp(stderr);
  abort();
}
void LamportSignature::keyGenerate(){
  cout<<endl<<"Generowanie kluczy"<<endl;
  keyXGenerate();
  keyYGenerate();
}
void LamportSignature::keyXGenerate(){
  RAND_poll();
  //cout<<"Klucz X :"<<endl;
  for(int i=0;i<N2;i++){
    RAND_bytes(X[i],N);
  }
  /*for (int i = 0; i < 16; i++){
    for(int j = 0; j < N; j++)
      printf("%02x", X[i][j]);
      cout<<endl;
  }/*
}
void LamportSignature::keyYGenerate(){
  //cout<<endl<<"Klucz Y :"<<endl;
  for(int i =0; i < N2; i++){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx == NULL)
      error();
    if(EVP_DigestInit_ex(ctx,EVP_blake2s256(),NULL) != 1)
      error();
    if(EVP_DigestUpdate(ctx,X[i],N) != 1)
      error();
    if(EVP_DigestFinal_ex(ctx,Y[i],&y_len) != 1)
      error();
    EVP_MD_CTX_free(ctx);
  }
  /*for (int i = 0; i < N2; i++){
    for(int j = 0; j < N; j++)
      printf("%02x", Y[i][j]);
      cout<<endl;
  }*/
}
void LamportSignature::signatureGenerate(){
  int k=0;
  for(int i=0; i<N;i++){
    bitset<8> D(d[i]);
    for(int j = 7; j>=0; j--){
      if(D[j] == 0)
        printf("%02x\n", X[k][0]);//w przypisaniu caly wiersz
      else
        printf("%02x\n", X[k+1][0]);
      k+=2;
    }
  }
}
