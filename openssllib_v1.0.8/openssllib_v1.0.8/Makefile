
CC=gcc





testm:tests_speed.o
	$(CC)  $(LDFLAGS) tests_speed.o  -o testm   -lcrypto -ldl -lpthread  -L./  


tests_speed.o:tests_speed.c
	$(CC) $(CFLAGS) -c tests_speed.c -I./include -I./

clean:
	rm *.o testm
