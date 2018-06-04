CC=gcc

testm:test-malleability.o
	$(CC) $(LDFLAGS) test-malleability.o -o testm -lcrypto -ldl -L./lib

test-malleability.o:test-malleability.c
	$(CC) $(CFLAGS) -I./include -g -c test-malleability.c 

clean:
	rm *.o testm
