cmd_/home/inada-n/work/kmemcached/libmp/byteorder.o := gcc -Wp,-MD,/home/inada-n/work/kmemcached/libmp/.byteorder.o.d  -nostdinc -isystem /usr/lib/gcc/x86_64-redhat-linux/4.4.6/include -Iinclude  -I/usr/src/kernels/2.6.32-279.11.1.el6.x86_64/arch/x86/include -include include/linux/autoconf.h -D__KERNEL__ -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -fno-delete-null-pointer-checks -O2 -m64 -mtune=generic -mno-red-zone -mcmodel=kernel -funit-at-a-time -maccumulate-outgoing-args -fstack-protector -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -pipe -Wno-sign-compare -fno-asynchronous-unwind-tables -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -Wframe-larger-than=2048 -Wno-unused-but-set-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -g -pg -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fno-dwarf2-cfi-asm -fconserve-stack  -DMODULE -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(byteorder)"  -D"KBUILD_MODNAME=KBUILD_STR(kmemcached)" -D"DEBUG_HASH=12" -D"DEBUG_HASH2=43" -c -o /home/inada-n/work/kmemcached/libmp/.tmp_byteorder.o /home/inada-n/work/kmemcached/libmp/byteorder.c

deps_/home/inada-n/work/kmemcached/libmp/byteorder.o := \
  /home/inada-n/work/kmemcached/libmp/byteorder.c \
  /home/inada-n/work/kmemcached/libmp/byteorder.h \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbdaf.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  /usr/src/kernels/2.6.32-279.11.1.el6.x86_64/arch/x86/include/asm/types.h \
    $(wildcard include/config/x86/64.h) \
    $(wildcard include/config/highmem64g.h) \
  include/asm-generic/types.h \
  include/asm-generic/int-ll64.h \
  /usr/src/kernels/2.6.32-279.11.1.el6.x86_64/arch/x86/include/asm/bitsperlong.h \
  include/asm-generic/bitsperlong.h \
  include/linux/posix_types.h \
  include/linux/stddef.h \
  include/linux/compiler.h \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
  include/linux/compiler-gcc4.h \
  /usr/src/kernels/2.6.32-279.11.1.el6.x86_64/arch/x86/include/asm/posix_types.h \
    $(wildcard include/config/x86/32.h) \
  /usr/src/kernels/2.6.32-279.11.1.el6.x86_64/arch/x86/include/asm/posix_types_64.h \

/home/inada-n/work/kmemcached/libmp/byteorder.o: $(deps_/home/inada-n/work/kmemcached/libmp/byteorder.o)

$(deps_/home/inada-n/work/kmemcached/libmp/byteorder.o):
