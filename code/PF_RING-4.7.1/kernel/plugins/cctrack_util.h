/*
 * cctrack_util.h
 *
 *
 * Copyright (c) 2011, Cornelius Diekmann
 * All rights reserved.
 */

#ifndef CCTRACK_UTIL_H_
#define CCTRACK_UTIL_H_

#include <linux/types.h>
#include "cctrack.h"

/**
 * helper function:
 * little to big endian, big to little endian, network to host byte order
 *
 */
static uint32_t inline endian_swap(uint32_t x){
	x = (x>>24) |
			((x<<8) & 0x00FF0000) |
			((x>>8) & 0x0000FF00) |
			(x<<24);
	return x;
};


static int inline is_power_of_two(u32 x){
	return x && !( (x-1) & x );
};

//#ifndef DEBUG
//#define assert(expr)
//#else
#define cctrack_assert(expr) \
	if(unlikely(!(expr))) {                                   \
		printk("Assertion failed! %s,%s,%s,line=%d\n", \
				#expr, __FILE__, __func__, __LINE__);          \
	}
//#endif

//run assertion after function is called the second time
//suitable for assertions which only hold after initialization
#define cctrack_assert_after2nd(expr) \
({						\
	static bool __assert_once;		\
						\
	if (__assert_once) {		\
		cctrack_assert(expr);	\
	}					\
	__assert_once = true; 	\
})

#define cctrack_assert_after3nd(expr) \
({						\
	static int __assert_once;		\
						\
	if (__assert_once >= 2) {			\
		cctrack_assert(expr);	\
	}	\
	if (__assert_once < 2) {			\
		__assert_once++;		\
	}	\
})


#define cctrack_printk_once(fmt, ...)			\
({						\
	static bool __print_once;		\
						\
	if (!__print_once) {			\
		__print_once = true;		\
		printk(fmt, ##__VA_ARGS__);	\
	}					\
})




/* COMPILE TIME ASSERT */
// by http://www.pixelbeat.org/programming/gcc/static_assert.html
/* Note we need the 2 concats below because arguments to ##
 * are not expanded, so we need to expand __LINE__ with one indirection
 * before doing the actual concatenation. */
#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b) ASSERT_CONCAT_(a, b)
#define ct_assert(e) enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1/(!!(e)) }



#endif /* CCTRACK_UTIL_H_ */
