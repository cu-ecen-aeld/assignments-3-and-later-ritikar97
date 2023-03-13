# References : ../examples/autotest-validate/Makefile
#			   https://www.gnu.org/software/make/manual/html_node/Conditional-Example.html



CC := gcc
SRC := writer.c
TARGET := writer
CFLAGS := -Wall -Werror

all: ${SRC}
	$(CROSS_COMPILE)$(CC) $(CFLAGS) ${SRC} -o ${TARGET}

clean:
	rm -f *.o ${TARGET}