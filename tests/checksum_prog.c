/*
 * References for using error detection algorithms 
   -----------------------------------------------

   Hamming Distance, Data Word, Code Word, Hamming Code for Error Correction
   
   https://users.ece.cmu.edu/~koopman/pubs/KoopmanCRCWebinar9May2012.pdf

   http://refspecs.linuxbase.org/LSB_3.0.0/LSB-PDA/LSB-PDA/zlib-adler32-1.html

   https://software.intel.com/en-us/articles/fast-computation-of-adler32-checksums

   http://ww1.microchip.com/downloads/en/appnotes/00730a.pdf

   http://www.ross.net/crc/download/crc_v3.txt

   Mark Adler on stack overflow :

   This is a mathematical property of CRCs. If a "pure" CRC without pre or post-processing,
   is appended to the message, then the CRC of the whole thing will always be zero. In fact
   this simplifies the checking of messages with CRCs in hardware, since you can just run the
   entire message and CRC through the CRC register, and check that the result at the end is zero.

   In this case there is pre and post-processing (the ^ 0xFFFFFFFFs). Then the result is not zero,
   but a different constant. That constant is simply the CRC of the message "00 00 00 00".

   Sample Codes building CRC Tables (quick long division)
   ------------------------------------------------------

 * Instead of performing a straightforward calculation of the 32 bit
 * CRC using a series of logical operations, this program uses the
 * faster table lookup method.  This routine is called once when the
 * program starts up to build the table which will be used later
 * when calculating the CRC values.

 #define CRC32_POLYNOMIAL     0xEDB88320L

 void BuildCRCTable()
 {
    int i;
    int j;
    unsigned long crc;

    for ( i = 0; i <= 255 ; i++ ) {
        crc = i;
        for ( j = 8 ; j > 0; j-- ) {
            if ( crc & 1 )
                crc = ( crc >> 1 ) ^ CRC32_POLYNOMIAL;
            else
                crc >>= 1;
        }
        CRCTable[ i ] = crc;
    }
 }

 * This routine calculates the CRC for a block of data using the
 * table lookup method. It accepts an original value for the crc,
 * and returns the updated value.

 unsigned long CalculateBufferCRC( count, crc, buffer )
 unsigned int count;
 unsigned long crc;
 void *buffer;
 {
    unsigned char *p;
    unsigned long temp1;
    unsigned long temp2;

    p = (unsigned char*) buffer;
    while ( count-- != 0 ) {
        temp1 = ( crc >> 8 ) & 0x00FFFFFFL;
        temp2 = CRCTable[ ( (int) crc ^ *p++ ) & 0xff ];
        crc = temp1 ^ temp2;
    }
    return( crc );
 }

static inline uint32_t adler_cksum(void *buf, size_t length)
{
        uint64_t i;
        uint32_t a = 1, b = 0;
        const uint32_t MOD_ADLER = 65521;

        for (i = 0; i < length; i+=8) {
                a = (a + ((uint64_t *)buf)[i]) % MOD_ADLER;
                b = (b + a) % MOD_ADLER;
        }
        return ((b << 16) | a);
}

 Adler error detection is weaker to CRC due to its limited universe for code words 65521
*
*/

// gcc checksum_test.c -lz

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <zlib.h> //crc32

#define TEST_BUFFER_SIZE 128

static uint64_t cpu_ticks_rdtsc(void)
{
#ifdef __x86_64__
        uint64_t high = 0;
        uint64_t low  = 0;

        __asm__ __volatile__ ("lfence");
        __asm__ __volatile__ ("rdtsc" : "=a"(low), "=d"(high));
        return (low | (high << 32));
#else
        // ! x86_64
#error "Need function to read CPU clock timestamp for this instruction set."
#endif
}

static inline unsigned long crc_get(void *buf, size_t length)
{
        unsigned long crc;
        crc = crc32(0, Z_NULL, 0);
        crc = crc32(crc, buf, TEST_BUFFER_SIZE);
        return crc;
}

static inline unsigned long adler_get(void *buf, size_t length)
{
        unsigned long adler;
        adler = adler32(0L, Z_NULL, 0);
        adler = adler32(adler, buf, TEST_BUFFER_SIZE);
        return adler;
}

int main()
{
        char *buf;
        unsigned long val;
        uint64_t start_tick, end_tick;
       
        buf = malloc(TEST_BUFFER_SIZE);
        if (!buf)
                return -ENOMEM;

        memset(buf, 0x00, TEST_BUFFER_SIZE);

        start_tick = cpu_ticks_rdtsc();
        val = crc_get(buf, TEST_BUFFER_SIZE);
        end_tick = cpu_ticks_rdtsc();
        printf("crc32 :%lx, delta cycles :%lu\n", val, (end_tick - start_tick));

        start_tick = cpu_ticks_rdtsc();
        val = adler_get(buf, TEST_BUFFER_SIZE);
        end_tick = cpu_ticks_rdtsc();
        printf("adler32 :%lu, delta cycles :%lu\n", val, (end_tick - start_tick));
        return 0;
}
