all:
	mkdir bin
	gcc src/main.c -lpcap -w -o bin/main.out

clean:
	rm -f bin/main.out
	rm -d bin

run:
	./bin/main.out