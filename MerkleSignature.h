#include<iostream>
#include<cmath>
#include<stack>
#include <cstdlib>
#include <ctime>

#include "podpis_Lamporta/LamportSignature.h"

using namespace std;
#define N 32
#define N2 N*16

struct Node{
  int height;
  unsigned char V[N2][N];
};

struct Signature{
  int index;
  unsigned char ots[N*8][N];
  unsigned char Y[N2][N];
  Node **authenticationPath;
};

class MerkleSignature
{
  int H;// wysokość drzewa
  int singsNumber;
  unsigned char publicKey[N2][N];
  //tablice podpisów ots
  LamportSignature *signs;
  // struktura opisująca podpis Merkle'a
  Signature signature;
  //drzewo skrótów
  Node **hashTree;
  //generowanie ścieżki uwierzytelniania
  void authenticationPathGenerate(int index);
  void error();
  //inicjalizacja drzewa skótów
  Node** initHashTree();
  //zapis podpisu do pliku
  void saveSignatureIntoFile();
  //odczyt podpisu z pliku
  void readSignatureFromFile(string fileName);
  //algorytm treehash - obliczanie węzła na danej wysokości i liścia
  Node* treehash(int height);
  //obliczanie wartości liścia
  Node* calcLeaf(int index);
  Node* calcPLeaf();
  //obliczanie wartości nowego węzła
  Node* calcNode(Node* nL,Node* nR, int index);
  public:
    //tworzenie podpisu H
     MerkleSignature(int H);
     //generowanie kluczy
     void keysGenerate();
     //obliczanie korzenia drzewa - klucza publicznego
     void publicKeyGenerate();
     //generowanie podpisu
     void signatureGenerate(string messageFileName);
     void showPublicKey();
     //weryfikacja podpisu
     void signatureVerify(string fileNameM,string fileNameL, string messageFileName);
     //weryfikacja klucza Y
     int keyYVerify();

     ~MerkleSignature();
};
