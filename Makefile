CC := gcc
CFLAGS := -Wall -Wextra -g -lpcap -lsqlite3 -lbsd
LDFLAGS := -Iheaders/
SRCDIR := ./src
OBJDIR := ./obj
SRC = $(wildcard src/*.c)
OBJ := $(SRC:src%.c=obj%.o)
BIN := bigmacd

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $(BIN)

$(OBJ): $(SRC)
	$(CC) $(LDFLAGS) $(CFLAGS) -c $(SRC)
	mv *.o $(OBJDIR)

.PHONY:clean
clean:
	rm $(OBJ) $(BIN)
