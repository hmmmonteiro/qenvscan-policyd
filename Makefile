all: qenvscan-policyd

foo: qenvscan-policyd.o

clean:
	rm -f qenvscan-policyd qenvscan-policyd.o *~ core

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@