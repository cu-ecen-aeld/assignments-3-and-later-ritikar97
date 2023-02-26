# References : ../examples/autotest-validate/Makefile



CC := gcc
SRC := aesdsocket.c
TARGET := aesdsocket
CFLAGS := -Wall -Werror

all: ${SRC}
	$(CROSS_COMPILE)$(CC) $(CFLAGS) ${SRC} -o ${TARGET}

clean:
	rm -f *.o ${TARGET}