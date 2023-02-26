# References : ../examples/autotest-validate/Makefile



CC := gcc
SRC := aesdsocket.c
TARGET := aesdsocket
CFLAGS := -Wall -Werror -g

all: $(TARGET)

$(TARGET) : ${SRC}
	$(CROSS_COMPILE)$(CC) $(CFLAGS) ${SRC} -o ${TARGET}

clean:
	rm -f *.o ${TARGET}