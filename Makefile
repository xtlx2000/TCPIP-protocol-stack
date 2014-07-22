all: host forwarder
host: host.o apptimer.o
	gcc -g -o host host.o apptimer.o -lpthread -std=gnu99 
host.o: msg.h list.h host.c
	gcc -g -c host.c -std=gnu99

forwarder: forwarder.o apptimer.o
	gcc -g -o forwarder forwarder.o apptimer.o -lpthread -std=gnu99 
forwarder.o: msg.h list.h forwarder.c
	gcc -g -c forwarder.c -std=gnu99

apptimer.o: apptimer.h list.h apptimer.c
	gcc -c apptimer.c -std=gnu99

clean:
	rm forwarder.o host.o host forwarder apptimer.o
