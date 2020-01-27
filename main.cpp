#include <iostream>
#include "MerkleSignature.h"
using namespace std;
int main(int argc, char *argv[]){

  MerkleSignature mSign(8);
  mSign.keysGenerate();
  mSign.publicKeyGenerate();

  mSign.signatureGenerate("tekst.txt");
  
  mSign.signatureVerify("podpisMerklea.bin","podpisLamporta.bin","tekst.txt");

  return 0;
}
