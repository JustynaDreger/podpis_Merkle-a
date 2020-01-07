#include "MerkleSignature.h"

MerkleSignature::MerkleSignature(int n)
{
  //http://graphics.stanford.edu/~seander/bithacks.html
  if(n && !(n & (n - 1))){
    singsNumber = n;
    H=log2(singsNumber);
    cout<<"Wysokość drzewa: "<<H<<endl;
  }
  else{
    cout<<"Błędny argument! argument musi być potęgą liczby 2."<<endl;
  }
  signs = new LamportSignature[singsNumber];
  hashTree=initHashTree();
}
void MerkleSignature::keysGenerate(){
  cout<<"Generowanie kluczy"<<endl;
  for(int i=0;i<singsNumber;i++){
    signs[i].keyGenerate();
    //cout<<"KLUCZ "<<i<<endl;
  }
  //cout<<endl<<endl;
}
Node** MerkleSignature::initHashTree(){
  Node **tree = new Node* [H];
  int a;
  for(int i=0;i<H;i++){
    a = 8/pow(2,i);
    //cout<<a<<endl;
    tree[i] = new Node[a];
  }
  return tree;
}
void MerkleSignature::showPublicKey(){
  cout<<endl<<"Klucz publiczny"<<endl;
  for (int i = 0; i < N2; i++){
    for(int j = 0; j < N; j++)
      printf("%02x", publicKey[i][j]);
    cout<<endl;
  }
}
void MerkleSignature::publicKeyGenerate(){
  cout<<"Generowanie klucza publicznego"<<endl;
  Node* p = treehash(H);
  memcpy(publicKey, p->V, sizeof publicKey);
  delete p;
}
Node* MerkleSignature::treehash(int maxheight){
  int leaf = 0;
  int *index = new int[maxheight-1];
  for(int i = 0; i<maxheight-1; i++)
    index[i] = 0;
  stack<Node*> tree;
  do{
    Node* nR;
    Node* nL;
    if(!tree.empty() && tree.size() > 1){
      nR = tree.top();
      tree.pop();
      nL = tree.top();
      tree.pop();
      if(nL->height == nR->height){
        //cout<<"Obliczanie nowego wezla dla wysokosci: "<<nR->height+1<<endl;
        Node* nP = calcNode(nL,nR, index[nR->height]);
        index[nP->height-1]++;
        if(nP->height == maxheight){
          //cout<<"Korzen:\t"<<"\t"<<nP->height<<endl;
          return nP;
        }
        tree.push(nP);
      }
      else{
        tree.push(nL);
        tree.push(nR);
        //cout<<"Nowa para lisci"<<endl;
        nL = calcLeaf(leaf);
        tree.push(nL);
        leaf++;
        nR = calcLeaf(leaf);
        tree.push(nR);
        leaf++;
      }
    }
    else{
      //cout<<"Nowa para lisci"<<endl;
      nL = calcLeaf(leaf);
      tree.push(nL);
      leaf++;
      nR = calcLeaf(leaf);
      tree.push(nR);
      leaf++;
    }
  }while(1);
}
Node* MerkleSignature::calcLeaf(int index){
  Node* n = new Node;
  n->height = 0;
  unsigned int len;
  for(int i =0; i < N2; i++){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx == NULL)
      error();
    if(EVP_DigestInit_ex(ctx,EVP_sha3_256(),NULL) != 1)
      error();
    if(EVP_DigestUpdate(ctx,signs[index].Y[i],N) != 1)
      error();
    if(EVP_DigestFinal_ex(ctx,n->V[i],&len) != 1)
      error();
    EVP_MD_CTX_free(ctx);
  }
  //cout<<"Lisc:\t"<<index<<endl;
  hashTree[0][index].height = n->height;
  memcpy(hashTree[0][index].V, n->V, sizeof hashTree[0][index].V);

  return n;
}
Node* MerkleSignature::calcNode(Node* nL,Node* nR, int index){
  //cout<<"Nowy wezel "<<endl;
  Node* n = new Node;
  int h = nL->height+1;
  n->height = h;

  unsigned int len;
  for(int i =0; i < N2; i++){
    unsigned char valuePom[N*2];
    memcpy(valuePom, nL->V[i],N);
    memcpy(valuePom+sizeof(nL->V[i]),nR->V[i],N);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx == NULL)
      error();
    if(EVP_DigestInit_ex(ctx,EVP_sha3_256(),NULL) != 1)
      error();
    if(EVP_DigestUpdate(ctx,valuePom,N*2) != 1)
      error();
    if(EVP_DigestFinal_ex(ctx,n->V[i],&len) != 1)
      error();
    EVP_MD_CTX_free(ctx);
  }

  if(h<H && index!=-1){
    hashTree[h][index].height = n->height;
    memcpy(hashTree[h][index].V, n->V, sizeof hashTree[h][index].V);
  }
  return n;
}
void MerkleSignature::signatureGenerate(string messageFileName){
  cout<<"Generowanie podpisu Merkle'a"<<endl;
  srand( time( NULL ) );
  int idx= rand()%singsNumber;
  signature.index = idx;
  signs[idx].signatureGenerate(messageFileName);//generowanie podpisu OTS
  //signs[signature.index].showSignature();
  memcpy(signature.ots, signs[idx].s, sizeof signs[idx].s);
  memcpy(signature.Y, signs[idx].Y, sizeof signs[idx].Y);
  //generowanie ścieżki uwierzytelniania
  authenticationPathGenerate(idx);
  //zapis do pliku
  saveSignatureIntoFile();
}
void MerkleSignature::authenticationPathGenerate(int index){
  cout<<"Generowanie ścieżki uwierzytelniającej"<<endl;
  signature.authenticationPath = new Node*[H];
  for(int h=0;h<H;h++){
    int pom = index/pow(2,h);
    if((pom%2)==1){
      int a =(index/pow(2,h))-1;
      signature.authenticationPath[h] = &hashTree[h][a];
      //cout<<"V"<<h<<a<<endl;
    }
    else{
      int a =(index/pow(2,h))+1;
      signature.authenticationPath[h] = &hashTree[h][a];
      //cout<<"V"<<h<<a<<endl;
    }
  }
}
void MerkleSignature::saveSignatureIntoFile(){
  FILE *fp = fopen("podpisMerklea.bin","wb");
  //zapis indexu
  fprintf(fp,"%d\n",signature.index);
  //zapis ots
  fwrite(signature.ots,sizeof(char),N*8*N,fp);
  //zapis klucza publicznego ots Y
  fwrite(signature.Y,sizeof(char),N2*N,fp);
  for(int i=0;i<H;i++){
    fwrite(signature.authenticationPath[i]->V,sizeof(char),N2*N,fp);
  }
  fclose(fp);
  cout<<"Podpis zapisano do pliku: podpisMerklea.bin"<<endl;
}
void MerkleSignature::readSignatureFromFile(string fileName){
  FILE *fp = fopen(fileName.c_str(),"rb");
  fscanf(fp,"%d\n",&signature.index);
  fread(&signature.ots,sizeof(char),N*8*N,fp);
  fread(&signature.Y,sizeof(char),N2*N,fp);
  for(int i=0;i<H;i++){
    fread(&signature.authenticationPath[i]->V,sizeof(char),N2*N,fp);
  }
  fclose(fp);
}
void MerkleSignature::error(){
  ERR_print_errors_fp(stderr);
  abort();
}
MerkleSignature::~MerkleSignature(){
  delete[] signs;
  for (int i=0;i<H;i++){
    delete[] hashTree[i];
  }
  delete[] hashTree;
}
void MerkleSignature::signatureVerify(string fileNameM,string fileNameL,string messageFileName){
  cout<<"Weryfikacja podpisu Merkle'a"<<endl;
  readSignatureFromFile(fileNameM);
  //cout<<signature.index<<endl;
  //werifikacja podpisu ots
  LamportSignature sign(messageFileName,fileNameL);
  int czy = sign.signatureVerify(fileNameL);
  if(czy==0){
    int czy2 = keyYVerify();
    if(czy2 == 0){
      cout<<"Podpis Merkle'a jest POPRAWNY"<<endl;
    }
    else{
      cout<<"Podpis Merkle'a jest BŁĘDNY"<<endl;
    }
  }
}
int MerkleSignature::keyYVerify(){
  Node* p;
  p = calcPLeaf();
  for(int h=1;h<=H;h++){
    int pom = signature.index/pow(2,h-1);
    if((pom%2)==1){
      p = calcNode(signature.authenticationPath[h-1],p,-1);
    }
    else{
      p = calcNode(p,signature.authenticationPath[h-1],-1);
    }
  }

  for(int i=0;i<N2;i++){
      if(memcmp(p->V[i],publicKey[i],N) != 0){
        return 1;
      }
  }
  return 0;
}
Node* MerkleSignature::calcPLeaf(){
  Node* n = new Node;
  n->height = 0;
  unsigned int len;
  for(int i =0; i < N2; i++){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx == NULL)
      error();
    if(EVP_DigestInit_ex(ctx,EVP_sha3_256(),NULL) != 1)
      error();
    if(EVP_DigestUpdate(ctx,signature.Y[i],N) != 1)
      error();
    if(EVP_DigestFinal_ex(ctx,n->V[i],&len) != 1)
      error();
    EVP_MD_CTX_free(ctx);
  }
  return n;
}
