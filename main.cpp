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

  MerkleSignature mSign(8);
  mSign.keysGenerate();
  mSign.publicKeyGenerate();
  //cout<<"DRZEWOOOOO"<<endl;
  //mSign.showHashTree();
  //mSign.showPublicKey();
  mSign.signatureGenerate("tekst.txt");

  mSign.signatureVerify("podpisLamporta.bin","tekst.txt");
  return 0;
}
