
all: ../libutp.a
	gcc main.c ../libutp.a -I ../ -lstdc++ -o utp-client -g

clean:
	rm -rf utp-client

utpclean:
	make -C ../ clean

../libutp.a:
	make -C ../
