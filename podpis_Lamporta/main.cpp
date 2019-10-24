//podpis dokumentu za pomocą schematu podpisu jednorazowego Lamporta-Diffiego

#include <iostream>
#include "LamportSignature.h"
using namespace std;
int main(int argc, char *argv[]){
  LamportSignature sign;
  sign.keyGenerate();
  sign.signatureGenerate();
  return 0;
}
