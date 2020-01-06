CPP=g++
OPENSSL_LIBS=-L/usr/local/openssl-1.1.1d/lib -lssl -lcrypto
OPENSSL_HEADER=-I/usr/local/openssl-1.1.1d/include
EJDB2=-lejdb2

all:
	$(CPP) -std=c++2a -Wall -pedantic -fpermissive -o main main.cpp MerkleSignature.cpp MerkleTree.cpp podpis_Lamporta/LamportSignature.cpp $(OPENSSL_HEADER) $(OPENSSL_LIBS) $(EJDB2)
