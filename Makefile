CC=gcc
CFLAGS=

build/rootkitdev_genheaders:
	mkdir -p build;
	$(CC) $(CFLAGS) src/*.c -o $@

.PHONY:install
install:build/rootkitdev_genheaders
	mkdir -p /usr/local/bin
	cp build/rootkitdev_genheaders /usr/local/bin/rootkitdev_genheaders

.PHONY:uninstall
uninstall:
	rm /usr/local/bin/rootkitdev_genheaders

.PHONY:clean
clean:
	rm -rf build
