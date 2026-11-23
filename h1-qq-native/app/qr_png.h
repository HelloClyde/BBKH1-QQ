#ifndef H1QQ_QR_PNG_H
#define H1QQ_QR_PNG_H
#include <stdint.h>
/* QQ's non-interlaced one-bit grayscale QR PNG, up to 512x512 / 16 KiB.
 * Large images shrink on their exact integer grid to at most 160x160.
 * The 360x360 native4 QR becomes 135x135; zero=black, one=white. */
int qq_qr_png(const uint8_t *,unsigned,uint8_t pixels[200*200],unsigned *width,unsigned *height);
#endif
