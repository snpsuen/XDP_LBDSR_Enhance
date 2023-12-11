CLANG = clang
CFLAGS = -g -O2 -Wall -Wextra

PROGS = xdp_lbdsr

all: $(PROGS)

clean:
	rm -f $(PROGS)
	rm -f vmlinux.h *.bpf.o *.skel.h

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf -c $<

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

$(PROGS): %: %.c %.skel.h
	$(CC) $(CFLAGS) -o $@ $< -lbpf

.PHONY: all clean

.DELETE_ON_ERROR:
.SECONDARY:
