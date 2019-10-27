//podpis dokumentu za pomocą schematu podpisu jednorazowego Lamporta-Diffiego

#include <iostream>
#include "LamportSignature.h"
using namespace std;
int main(int argc, char *argv[]){
  LamportSignature sign;
  //sign.showDigest();
  sign.keyGenerate();
  //sign.showKeyX();
  //sign.showKeyY();
  sign.signatureGenerate();
  //sign.showSignature();
  sign.signatureVerifite();
  return 0;
}
