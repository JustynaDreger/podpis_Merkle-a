#include<iostream>

using namespace std;
#define N 32
#define N2 N*16
struct Node
{
  Node *left;
  Node *rigth;
  unsigned char V[N2][N];
};

class MerkleSignature
{
  int H;// wysokość drzewa Merkle'a
  Node *publicKey;
  public:
    //tworzenie podpisu
     MerkleSignature(int H);
};
