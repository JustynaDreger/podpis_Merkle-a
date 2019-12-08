//podpis dokumentu za pomocą schematu podpisu jednorazowego Lamporta-Diffiego

#include <iostream>
//#include "podpis_Lamporta/LamportSignature.h"
#include "MerkleSignature.h"
using namespace std;
int main(int argc, char *argv[]){
//generowanie podpisu wiadomosci tekst.txt, zapisanego w pliku podpis.bin
  //LamportSignature sign;
  //sign.showDigest();
  //sign.keyGenerate();
  //sign.showKeyX();
  //sign.showKeyY();
  //sign.signatureGenerate("tekst.txt");
  //sign.showSignature();
//weryfikacja podpisu
  //LamportSignature sign2("tekst.txt","podpis.bin");
  //sign2.showKeyY();
  //sign2.signatureVerify("podpis.bin");

  MerkleSignature mSign(2);
  mSign.keysGenerate();
  mSign.publicKeyGenerate();
  mSign.showPublicKey();
  return 0;
}