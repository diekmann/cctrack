#
# Makefile for the PF_RING API example programs
#
# Try to make both programs written on top of the
# PF_RING library and programs originally written
# on top of PCAP library and linked now to use
# the version with PF_RING aware functionalities.
#



#
# PF_RING
#
PFRINGDIR  = ../lib
LIBPFRING  = ${PFRINGDIR}/libpfring.a

#
# DNA Support
DNA_DEFINE = #-DENABLE_DNA_SUPPORT

#
# PF_RING aware libpcap
#
O_FLAG     = #-O2
EXTRA_LIBS = #-ldag
PCAPDIR    = ../libpcap-1.1.1-ring
LIBPCAP    = ${PCAPDIR}/libpcap.a  ${EXTRA_LIBS}

#
# Search directories
#
PFRING_KERNEL=../../kernel
INCLUDE    = -I${PFRING_KERNEL} -I${PFRING_KERNEL}/plugins -I${PFRINGDIR} -I${PCAPDIR}

#
# C compiler and flags
#
#
# CROSS_COMPILE=arm-mv5sft-linux-gnueabi-
#
CC         = ${CROSS_COMPILE}gcc #--platform=native
CFLAGS     = -g ${O_FLAG} -Wall -Werror ${INCLUDE} ${DNA_DEFINE} #-O
# LDFLAGS  =

#
# User and System libraries
#
LIBS       = ${LIBPFRING} -lpthread #-ldag

# How to make an object file
%.o: %.c
#	@echo "=*= making object $@ =*="
	${CC} ${CFLAGS} -c $< -o $@

#
# Main targets
#
PFPROGS   = test_cctrack test_cctrack_dynamic test_cctrack_cluster


TARGETS   = ${PFPROGS}

all: ${TARGETS}


test_cctrack: test_cctrack.o ${LIBPFRING}
	${CC} test_cctrack.o ${LIBS} -o $@
	
test_cctrack_dynamic: test_cctrack_dynamic.o ${LIBPFRING}
	${CC} test_cctrack_dynamic.o ${LIBS} -o $@

test_cctrack_cluster: test_cctrack_cluster.o ${LIBPFRING}
	${CC} test_cctrack_cluster.o ${LIBS} -o $@

clean:
	@rm -f ${TARGETS} *.o *~
