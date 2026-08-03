/*
 * termio related ioctls
 */

struct linux_termio {
	unsigned short c_iflag;
	unsigned short c_oflag;
	unsigned short c_cflag;
	unsigned short c_lflag;
	unsigned char c_line;
	unsigned char c_cc[LINUX_NCC];
};

struct linux_termios {
	unsigned int c_iflag;
	unsigned int c_oflag;
	unsigned int c_cflag;
	unsigned int c_lflag;
	unsigned char c_line;
	unsigned char c_cc[LINUX_NCCS];
};

/*
 * The termios2 form, which is what a current glibc actually sends.
 *
 * Same fields as struct linux_termios with the two baud rates appended, and it
 * travels under a different set of ioctl numbers - TCGETS2 and friends, which
 * are _IOC-encoded rather than the bare 0x54xx the older calls use. glibc moved
 * to it so that an arbitrary baud rate could be asked for by number instead of
 * being chosen from the Bxxx list.
 */
struct linux_termios2 {
	unsigned int c_iflag;
	unsigned int c_oflag;
	unsigned int c_cflag;
	unsigned int c_lflag;
	unsigned char c_line;
	unsigned char c_cc[LINUX_NCCS];
	unsigned int c_ispeed;
	unsigned int c_ospeed;
};

struct linux_winsize {
	unsigned short ws_row, ws_col;
	unsigned short ws_xpixel, ws_ypixel;
};


