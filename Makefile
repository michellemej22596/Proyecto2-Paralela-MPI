CC=mpicc
CFLAGS=-O2
LDLIBS=-lcrypto

all: bruteforce_mpi

bruteforce_mpi: bruteforce_mpi.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f bruteforce_mpi
