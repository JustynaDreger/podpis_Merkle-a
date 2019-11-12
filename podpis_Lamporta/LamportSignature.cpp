#include "LamportSignature.h"

LamportSignature::LamportSignature(){
  string M;
  cout<<"Podaj wiadomosc :"<<endl;
  cin>>M;
  d_M(M);
}
void LamportSignature::d_M(string m){
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
  for(int i=0;i<N2;i++){
    RAND_bytes(X[i],N);
  }
}
void LamportSignature::keyYGenerate(){
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
}
void LamportSignature::signatureGenerate(){
  cout<<"Generowanie podpisu"<<endl;
  int k=0,l=0;
  //s = new unsigned char*[N*8];
  for(int i=0; i<N;i++){
    bitset<8> D(d[i]);
    for(int j = 7; j>=0; j--){
      //s[l] = new unsigned char[N];
      if(D[j] == 0){
        memcpy(s[l],&X[k][0],N);
      }
      else{
        memcpy(s[l],&X[k+1][0],N);
      }
      k+=2;
      l++;
    }
  }
  saveIntoFile();
}
void LamportSignature::signatureVerifite(string fileName){
  cout<<endl<<"Weryfikacja podpisu"<<endl;
  readFromFile(fileName);

  unsigned char fs[N*8][N];
  unsigned int fs_len;
  for(int i =0; i < N*8; i++){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx == NULL)
      error();
    if(EVP_DigestInit_ex(ctx,EVP_blake2s256(),NULL) != 1)
      error();
    if(EVP_DigestUpdate(ctx,s[i],N) != 1)
      error();
    if(EVP_DigestFinal_ex(ctx,fs[i],&fs_len) != 1)
      error();
    EVP_MD_CTX_free(ctx);
  }
  int fs_num = 0,k = 0;
  for(int i = 0; i<N; i++){
    bitset<8> D(d[i]);
    for(int j = 7; j>=0; j--){
      int l = (int)D[j];
      if(memcmp(fs[fs_num],Y[k+l],N) != 0){
        cout<<"Podpis jest BŁĘDNY"<<endl;
        return;
      }
      fs_num++;
      k+=2;
    }
  }
  cout<<"Podpis jest POPRAWNY"<<endl;
}
void LamportSignature::showDigest(){
  cout<<"Skrot :"<<endl;
  for (int i = 0; i < N; i++)
      printf("%02x", d[i]);
}
void LamportSignature::showKeyX(){
  cout<<"Klucz X:"<<endl;
  for (int i = 0; i < N2; i++){
    for(int j = 0; j < N; j++)
      printf("%02x", X[i][j]);
    cout<<endl;
  }
}
void LamportSignature::showKeyY(){
  cout<<"Klucz Y:"<<endl;
  for (int i = 0; i < N2; i++){
    for(int j = 0; j < N; j++)
      printf("%02x", Y[i][j]);
    cout<<endl;
  }
}
void LamportSignature::showSignature(){
  cout<<endl<<endl<<"PODPIS"<<endl;
  for (int i = 0; i < N*8; i++){
    for(int j = 0; j < N; j++)
      printf("%02x", s[i][j]);
    cout<<endl;
  }
}
void LamportSignature::saveIntoFile(){
  FILE *fp = fopen("podpis.bin","wb");
  fwrite(s,sizeof(char),N*8*N,fp);
  fclose(fp);
  cout<<"Podpis zapisano do pliku: podpis.bin"<<endl;
}
void LamportSignature::readFromFile(string fileName){
  //unsigned char ss[N*8][N];
  FILE *fp = fopen(fileName.c_str(),"rb");
  fread(&s,sizeof(char),N*8*N,fp);
  fclose(fp);
  /*cout<<endl<<endl<<"Z pliku"<<endl;
  for (int i = 0; i < N*8; i++){
    for(int j = 0; j < N; j++)
      printf("%02x", ss[i][j]);
    cout<<endl;
  }*/
}
