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
}
void MerkleSignature::keysGenerate(){
  cout<<"Generowanie kluczy"<<endl;
  for(int i=0;i<singsNumber;i++){
    signs[i].keyGenerate();
    cout<<"KLUCZ "<<i<<endl;
  }
  cout<<endl<<endl;
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
  Node* p = treehash(0,H);
  memcpy(publicKey, p->V, sizeof publicKey);
  delete p;
}
Node* MerkleSignature::treehash(int startNode, int maxheight){
  int leaf = startNode;
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
        cout<<"Obliczanie nowego wezla dla wysokosci: "<<nR->height+1<<endl;
        Node* nP = calcNode(nL,nR);
        if(nP->height == maxheight){
          cout<<"Korzen:\t"<<"\t"<<nP->height<<endl;
          return nP;
        }
        tree.push(nP);
      }
      else{
        tree.push(nL);
        tree.push(nR);
        cout<<"Nowa prara lisci"<<endl;
        nL = calcLeaf(leaf);
        tree.push(nL);
        leaf++;
        nR = calcLeaf(leaf);
        tree.push(nR);
        leaf++;
      }
    }
    else{
      cout<<"Nowa para lisci"<<endl;
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
  //unsigned char pom[N2][N] = signs[index].Y;
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

  cout<<"Lisc:\t"<<index<<endl;
  return n;
}
Node* MerkleSignature::calcNode(Node* nL,Node* nR){
  cout<<"Nowy wezel "<<endl;
  Node* n = new Node;
  n->height = nL->height+1;

  unsigned int len;
  for(int i =0; i < N2; i++){
    unsigned char valuePom[N*2];
    memcpy(valuePom, nL->V[i],N);
    memcpy(valuePom+sizeof(nL->V[i]),nR->V[i],N);
    /*cout<<"LEWY"<<endl;
      for(int j = 0; j < N; j++)
        printf("%02x", nL->V[0][j]);
      cout<<endl<<"PRAWY"<<endl;;
      for(int j = 0; j < N; j++)
        printf("%02x", nR->V[0][j]);
      cout<<endl<<"RAZEM"<<endl;
      for(int j = 0; j < N*2; j++)
        printf("%02x", valuePom[j]);
      cout<<endl;*/
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

  return n;
}
void MerkleSignature::signatureGenerate(string messageFileName){
  cout<<"Generowanie podpisu Merkle'a"<<endl;
  signature.index = 0;// zrobić generowanie indeksu
  signs[signature.index].signatureGenerate(messageFileName);//generowanie podpisu OTS
  //signs[signature.index].showSignature();
  memcpy(signature.ots, signs[signature.index].s, sizeof signs[signature.index].s);
  memcpy(signature.Y, signs[signature.index].Y, sizeof signs[signature.index].Y);
  //generowanie ścieżki uwierzytelniania
  //authenticationPathGenerate(signature.index);
}
void MerkleSignature::authenticationPathGenerate(int index){
  cout<<"Generowanie ścieżki uwierzytelniającej"<<endl;
  signature.authenticationPath = new Node*[H];
  for(int h=0;h<H;h++){
    int pom = index/pow(2,h);
    if((pom%2)==1){
      cout<<"V"<<h<<(index/pow(2,h)-1)<<endl;
      cout<<"Start liść: "<<pow(2,h)<<endl;
    }
    else{
      cout<<"V"<<h<<(index/pow(2,h)+1)<<endl;
      cout<<"Start liść: "<<pow(2,h)<<endl;
    }
  }
}
void MerkleSignature::error(){
  ERR_print_errors_fp(stderr);
  abort();
}
MerkleSignature::~MerkleSignature(){
  delete[] signs;
}
