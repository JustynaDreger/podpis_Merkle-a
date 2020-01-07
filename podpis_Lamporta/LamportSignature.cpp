#include "LamportSignature.h"

LamportSignature::LamportSignature(){

}
LamportSignature::LamportSignature(string messageFileName,string signatureFile){
  string M;
  M = readMessageFromFile(messageFileName);
  d_M(M);
  readSignatureFromFile(signatureFile);
  readFromDataBase();
}
LamportSignature::~LamportSignature(){
  delete[] d;
}
string LamportSignature::readMessageFromFile(string fileName){
  string s1, s2;
  ifstream file(fileName);
  while(getline(file,s1)){
    s2 = s2 + s1 + '\n';
  }
  file.close();
  return s2;
}
void LamportSignature::d_M(string m){
  cout<<"Obliczanie skrotu"<<endl;
  char M[m.size()+1];
  strcpy(M,m.c_str());

  d = new unsigned char[N];
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
  //cout<<endl<<"Generowanie kluczy"<<endl;
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
void LamportSignature::signatureGenerate(string messageFileName){
  cout<<"Generowanie podpisu Lamporta"<<endl;
  string M;
  M = readMessageFromFile(messageFileName);
  d_M(M);
  int k=0,l=0;
  for(int i=0; i<N;i++){
    bitset<8> D(d[i]);
    for(int j = 7; j>=0; j--){
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
  saveIntoDataBase();
  saveSignatureIntoFile();
}
int LamportSignature::signatureVerify(string fileName){
  cout<<"Weryfikacja podpisu Lamporta"<<endl;
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
        cout<<"Podpis Lamporta jest BŁĘDNY"<<endl;
        return 1;
      }
      fs_num++;
      k+=2;
    }
  }
  cout<<"Podpis Lamporta jest POPRAWNY"<<endl;
  return 0;
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
void LamportSignature::saveSignatureIntoFile(){
  FILE *fp = fopen("podpisLamporta.bin","wb");
  fprintf(fp,"%d\n",keyId);
  fwrite(s,sizeof(char),N*8*N,fp);
  fclose(fp);
  cout<<"Podpis zapisano do pliku: podpisLamporta.bin"<<endl;
}
void LamportSignature::readSignatureFromFile(string fileName){
  FILE *fp = fopen(fileName.c_str(),"rb");
  fscanf(fp,"%d\n",&keyId);
  fread(&s,sizeof(char),N*8*N,fp);
  fclose(fp);
}
string LamportSignature::convertKeyToString(){
  string wynik="";
  string temp1,temp2;
  int a;
  for(int i=0;i<N2;i++){
    for(int j=0;j<N;j++){
      temp1=to_string((int)Y[i][j]);
      a=strlen(temp1.c_str());
      if(a<3){
        for(int k=0;k<(3-a);k++)
          temp2='0'+temp2;
        wynik.append(temp2);
        temp2="";
      }
      wynik.append(temp1);
    }
  }
  return wynik;
}
void LamportSignature::convertKeyToUchar(string sKey){
  string temp;
  int k=0;
  for(int i=0;i<N2;i++){
    for(int j=0;j<N;j++){
      temp = sKey.substr(k, 3);
      Y[i][j]=(unsigned char)(stoi(temp));
      k+=3;
    }
  }
}
void LamportSignature::saveIntoDataBase(){
  EJDB_OPTS opts = {
    .kv = {
      .path = "LamportKeys.db",
      .oflags =0//IWKV_TRUNC
    }
  };
  EJDB db;
  int64_t id;
  JQL q = 0;
  JBL jbl = 0;

  iwrc rc = ejdb_init();// inicjalizacja
  RCHECK(rc);

  rc = ejdb_open(&opts, &db);//otwarcie pliku z baza (opcje otwarcia, uchwyt do bazy)
  RCHECK(rc);
  globalId= 0;
  rc =  jql_create(&q, "Y", "/**");
  RCGO(rc, finish);
  EJDB_EXEC ux = {
    .db = db,
    .q = q,
    .visitor = documents_visitor
  };
  freopen("/dev/null","a",stderr);
  rc = ejdb_exec(&ux);
  freopen ("/dev/tty", "a", stderr);
  string sId;
  keyId = (globalId/2)+1;
  if(globalId==0) sId=to_string(1);
  else sId =to_string(keyId);
  string sKey = convertKeyToString();
  string c ="{\"id\":\""+sId+"\", \"key\":\""+sKey+"\"}";
  rc = jbl_from_json(&jbl, c.c_str());
  RCGO(rc, finish);
  rc = ejdb_put_new(db, "Y", jbl, &id);
  RCGO(rc, finish);
  jbl_destroy(&jbl);
finish:
  if (q) jql_destroy(&q);
  if (jbl) jbl_destroy(&jbl);
  ejdb_close(&db);
  RCHECK(rc);

}
void LamportSignature::readFromDataBase(){
  EJDB_OPTS opts = {
    .kv = {
      .path = "LamportKeys.db",
      .oflags =0
    }
  };
  EJDB db;
  int64_t id;
  JQL q = 0;
  JBL jbl = 0;

  iwrc rc = ejdb_init();// inicjalizacja
  RCHECK(rc);

  rc = ejdb_open(&opts, &db);//otwarcie pliku z baza (opcje otwarcia, uchwyt do bazy)
  RCHECK(rc);
  globalId= 0;
  rc =  jql_create(&q, "Y", "/[id = :id]");
  RCGO(rc, finish);
  EJDB_EXEC ux = {
    .db = db,
    .q = q,
    .visitor = documents_visitor2
  };
  rc = jql_set_i64(q, "id", 0, keyId);
  RCGO(rc, finish);
  freopen("proba.txt","a",stdout);
  // Now execute the query
  rc = ejdb_exec(&ux);
  freopen ("/dev/tty", "a", stdout);
  string pom;
  ifstream file("proba.txt");
  getline(file,pom);
  string keyS = to_string(keyId);
  //cout<<keyId<<"\tDŁ -> "<<keyS.length()<<endl;
  string keyPom=pom.substr(16+keyS.length(),N*3*N2);
  //cout<<endl<<endl<<keyPom<<endl;
  convertKeyToUchar(keyPom);

  if(remove("proba.txt")!=0) cout<<"Problem z plikiem"<<endl;
finish:
  if (q) jql_destroy(&q);
  if (jbl) jbl_destroy(&jbl);
  ejdb_close(&db);
  RCHECK(rc);

}
static iwrc LamportSignature::documents_visitor(EJDB_EXEC *ctx, const EJDB_DOC doc, int64_t *step) {
  globalId+=jbl_count(doc->raw);
  //cout<<globalId<<endl;
  // Print document to stderr
  return jbl_as_json(doc->raw, jbl_fstream_json_printer, stderr, JBL_PRINT_PRETTY);
}
static iwrc LamportSignature::documents_visitor2(EJDB_EXEC *ctx, const EJDB_DOC doc, int64_t *step) {
  return jbl_as_json(doc->raw, jbl_fstream_json_printer, stdout, JBL_PRINT_CODEPOINTS);
}
