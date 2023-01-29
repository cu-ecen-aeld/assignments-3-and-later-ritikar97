# References : ../examples/autotest-validate/Makefile
#			   https://www.gnu.org/software/make/manual/html_node/Conditional-Example.html

ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
	CC := aarch64-none-linux-gnu-gcc
else 
	CC := gcc
endif


SRC := writer.c 
TARGET = writer
OBJS := $(SRC:.c=.o)
CFLAGS := -Wall -Werror

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $(TARGET)

clean:
	-rm -f *.o $(TARGET) 	