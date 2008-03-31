all: qenvscan-policyd

clean:
	rm -f qenvscan-policyd *~ core

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
