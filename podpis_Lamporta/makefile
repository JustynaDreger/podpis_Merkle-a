CPP=g++
OPENSSL_LIBS=-L/usr/local/openssl-1.1.1d/lib -lssl -lcrypto
OPENSSL_HEADER=-I/usr/local/openssl-1.1.1d/include
all:
	$(CPP) -std=c++1z -o main main.cpp LamportSignature.cpp $(OPENSSL_HEADER) $(OPENSSL_LIBS)
