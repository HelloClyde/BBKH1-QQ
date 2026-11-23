#ifndef H1QQ_PROFILE_H
#define H1QQ_PROFILE_H
#include <stdint.h>
/* Pinned native4 default config at 0x28cbea0 selects protocol 3:
 * Watch 9.0.1 NT, profile 0x28cc498 and flag 0x4d7=1.
 * It uses this profile for QR AND login, Dandelion energy (68 bytes),
 * T35/T521=111. The phone-only Watch2.0.8 override does not apply. */
#define QQ_NATIVE_SUB_APP_ID 537214131u
#define QQ_NATIVE_MISC_BITMAP 150470524u
#define QQ_NATIVE_MAIN_SIGMAP 34869472u
#define QQ_NATIVE_SSO_VERSION 18u
#define QQ_NATIVE_BUILD_TIME 1648001696u
#define QQ_NATIVE_APK_ID "com.tencent.qqlite"
#define QQ_NATIVE_VERSION "9.0.1"
#define QQ_NATIVE_SDK "6.0.0.2498"
#define QQ_NATIVE_QUA "V1_AND_SQ_8.9.68_0_RDM_B"
#define QQ_NATIVE_DEVICE_TYPE 111u
static inline void qq_native_device_id(const uint8_t guid[16],char id[33])
{static const char hex[]="0123456789abcdef";for(unsigned i=0;i<16;++i){id[2*i]=hex[guid[i]>>4];id[2*i+1]=hex[guid[i]&15];}id[32]=0;}
#endif
