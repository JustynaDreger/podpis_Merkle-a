CPP=g++
OPENSSL_LIBS=-L/usr/local/openssl-1.1.1d/lib -lssl -lcrypto
OPENSSL_HEADER=-I/usr/local/openssl-1.1.1d/include
MYSQL_FLAGS = -I/usr/include/mariadb -I/usr/include/mariadb/mysql
MYSQL_LIBS = -L/usr/lib/x86_64-linux-gnu/ -lmariadb
all:
	$(CPP) -std=c++1z -o main $(MYSL_FLAGS) main.cpp LamportSignature.cpp $(OPENSSL_HEADER) $(OPENSSL_LIBS) $(MYSQL_LIBS)
