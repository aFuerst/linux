// #include <stdint.h>
// #include <purgatory.h>

// #ifndef ARCH_I386_IO_H
// #define ARCH_I386_IO_H

// #include <stdint.h>
// /* Helper functions for directly doing I/O */

#include <linux/types.h>
#include "no_kvm.h"

// #endif /* ARCH_I386_IO_H */

// /*
//  * VGA
//  * =============================================================================
//  */

//* Simple VGA output */

#define VGABASE		((void *)0xb8000)

#define MAX_YPOS	25
#define MAX_XPOS	80

static int current_ypos = 1;
static int current_xpos = 0; 
uint8_t console_vga = 1;

__no_kvm_section __always_inline static void putchar_vga(int ch)
{
	int  i, k, j;
    return;
	if (!console_vga)
		return;

	if (current_ypos >= MAX_YPOS) {
		//* scroll 1 line up */
		for (k = 1, j = 0; k < MAX_YPOS; k++, j++) {
			for (i = 0; i < MAX_XPOS; i++) {
				no_kvm_writew(no_kvm_readw(VGABASE + 2*(MAX_XPOS*k + i)),
					VGABASE + 2*(MAX_XPOS*j + i));
			}
		}
		for (i = 0; i < MAX_XPOS; i++)
			no_kvm_writew(0x720, VGABASE + 2*(MAX_XPOS*j + i));
		current_ypos = MAX_YPOS-1;
	}
	if (ch == '\n') {
		current_xpos = 0;
		current_ypos++;
	} else if (ch != '\r')  {
		no_kvm_writew(((0x7 << 8) | (unsigned short) ch),
			VGABASE + 2*(MAX_XPOS*current_ypos +
				current_xpos++));
		if (current_xpos >= MAX_XPOS) {
			current_xpos = 0;
			current_ypos++;
		}
	}
}

/*
 * Serial
 * =============================================================================
 */

/* Base Address */
uint8_t console_serial = 1;
uint16_t serial_base = 0x3f8; /* TTYS0 */
uint32_t serial_baud = 0;

#define XMTRDY          0x20

#define DLAB		0x80

#define TXR             0       /*  Transmit register (WRITE) */
#define TBR             0       /*  Transmit register (WRITE) */
#define RXR             0       /*  Receive register  (READ)  */
#define IER             1       /*  Interrupt Enable          */
#define IIR             2       /*  Interrupt ID              */
#define FCR             2       /*  FIFO control              */
#define LCR             3       /*  Line control              */
#define MCR             4       /*  Modem control             */
#define LSR             5       /*  Line Status               */
#define MSR             6       /*  Modem Status              */
#define DLL             0       /*  Divisor Latch Low         */
#define DLH             1       /*  Divisor latch High        */

__no_kvm_section __always_inline static void serial_init(void)
{
	static int initialized = 0;
	if (!initialized) {
		unsigned lcr;
		no_kvm_outb(0x3, serial_base + LCR);	/* 8n1 */
		no_kvm_outb(0,   serial_base + IER);	/* no interrupt */
		no_kvm_outb(0,   serial_base + FCR);	/* no fifo */
		no_kvm_outb(0x3, serial_base + MCR);	/* DTR + RTS */
		
		lcr = no_kvm_inb(serial_base + LCR); 
		no_kvm_outb(lcr | DLAB, serial_base + LCR); 
		//* By default don't change the serial port baud rate */
		if (serial_baud) {
			unsigned divisor = 115200 / serial_baud; 
			no_kvm_outb(divisor & 0xff, serial_base + DLL); 
			no_kvm_outb((divisor >> 8) & 0xff, serial_base + DLH); 
		}
		no_kvm_outb(lcr & ~DLAB, serial_base + LCR);
		initialized = 1;
	}
}

__no_kvm_section __always_inline static void serial_tx_byte(unsigned byte)
{
	//* Ensure the serial port is initialized */
	serial_init();

	//* Wait until I can send a byte */
	// while((no_kvm_inb(serial_base + LSR) & 0x20) == 0)
	// 	;
	no_kvm_outb(byte, serial_base + TBR);
	//* Wait until the byte is transmitted */
	// while(!(no_kvm_inb(serial_base + LSR) & 0x40))
	// 	;
}

__no_kvm_section __always_inline static void putchar_serial(int ch)
{
	// if (!console_serial) {
	// 	return;
	// }
	if (ch == '\n') {
		serial_tx_byte('\r');
	}
	serial_tx_byte(ch);
}

//* Generic wrapper function */

__no_kvm_section __always_inline void putchar(int ch)
{
	putchar_vga(ch);
	putchar_serial(ch);
}

// #include <stdarg.h>
// #include <limits.h>
// #include <stdint.h>
// #include <purgatory.h>
// #include <string.h>

//*
//  * Output
//  * =============================================================================
//  */

#define LONG_LONG_SHIFT  ((int)((sizeof(unsigned long long)*CHAR_BIT) - 4))
#define LONG_SHIFT  ((int)((sizeof(unsigned long)*CHAR_BIT) - 4))
#define INT_SHIFT   ((int)((sizeof(unsigned int)*CHAR_BIT) - 4))
#define SHRT_SHIFT  ((int)((sizeof(unsigned short)*CHAR_BIT) - 4))
#define CHAR_SHIFT  ((int)((sizeof(unsigned char)*CHAR_BIT) - 4))

// /*
// void sprintf(char *buffer, const char *fmt, ...)
// {
// 	va_list args;

// 	va_start(args, fmt);
// 	vsprintf(buffer, fmt, args);
// 	va_end(args);
// }
// */

__no_kvm_section __always_inline void cust_printf(const char *fmt)
{
    return;
    // char *p;
	// for ( ; *fmt != '\0'; ++fmt) {
    //     putchar(*fmt);
    // }
    // /*
	// va_list args;

	// va_start(args, fmt);
	// vsprintf(0, fmt, args);
	// va_end(args);
    // */
}