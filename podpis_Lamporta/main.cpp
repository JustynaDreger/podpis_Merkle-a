//podpis dokumentu za pomocą schematu podpisu jednorazowego Lamporta-Diffiego

#include <iostream>
#include "LamportSignature.h"
using namespace std;
int main(int argc, char *argv[]){

  LamportSignature sign("tekst.txt");
  //sign.showDigest();
  sign.keyGenerate();
  //sign.showKeyX();
  //sign.showKeyY();
  sign.signatureGenerate();
  //sign.showSignature();

  LamportSignature sign2("tekst.txt","podpis.bin");
  //sign2.showKeyY();
  sign2.signatureVerify("podpis.bin");

  return 0;
}
