all:
	gcc main.c -lpcap -o a.out

clean:
	rm -f a.out

run:
	./a.out