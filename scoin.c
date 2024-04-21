#include <stdio.h>
#include <stdlib.h>

// SHA STUFF START -----------------------------------------------------------------
unsigned int sha_h[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

unsigned int sha_k[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

// set state to what it should be before processing the first chunk of a message
void sha_initstate(unsigned int *state)
{
    int n;

    for (n = 0; n < 8; n++)
    {
        *state = sha_h[n];
        state++;
    }
}

// process one chunk of a message, updating state (which after the last chunk is the hash)
void sha_processchunk(unsigned int *state, unsigned int *chunk)
{
    unsigned int w[64], s0, s1;
    unsigned int a, b, c, d, e, f, g, h;
    unsigned int t1, t2, maj, ch, S0, S1;
    int n;

    // Read in chunk. When these 32bit words were read, they should have been taken as big endian.
    for (n = 0; n < 16; n++)
        w[n] = *(chunk + n);

    // Extend the sixteen 32-bit words into sixty-four 32-bit words:
    for (n = 16; n < 64; n++)
    {
        s0 = (w[n - 15] >> 7 | w[n - 15] << (32 - 7)) ^ (w[n - 15] >> 18 | w[n - 15] << (32 - 18)) ^ (w[n - 15] >> 3);
        s1 = (w[n - 2] >> 17 | w[n - 2] << (32 - 17)) ^ (w[n - 2] >> 19 | w[n - 2] << (32 - 19)) ^ (w[n - 2] >> 10);
        w[n] = w[n - 16] + s0 + w[n - 7] + s1;
    }

    // Initialize hash value for this chunk:
    a = *(state + 0);
    b = *(state + 1);
    c = *(state + 2);
    d = *(state + 3);
    e = *(state + 4);
    f = *(state + 5);
    g = *(state + 6);
    h = *(state + 7);

    // Main loop:
    for (n = 0; n < 64; n++)
    {
        S0 = (a >> 2 | a << (32 - 2)) ^ (a >> 13 | a << (32 - 13)) ^ (a >> 22 | a << (32 - 22));
        maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        S1 = (e >> 6 | e << (32 - 6)) ^ (e >> 11 | e << (32 - 11)) ^ (e >> 25 | e << (32 - 25));
        ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + sha_k[n] + w[n];

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Add this chunk's hash to result so far:
    *(state + 0) += a;
    *(state + 1) += b;
    *(state + 2) += c;
    *(state + 3) += d;
    *(state + 4) += e;
    *(state + 5) += f;
    *(state + 6) += g;
    *(state + 7) += h;
}
// SHA STUFF END -------------------------------------------------------------------

unsigned int pad0[12] = {
    0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000280};

unsigned int pad1[8] = {0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000100};

int verifyhash(unsigned int *block)
{
    unsigned int state[8];
    unsigned int chunk[16];
    int n;
    unsigned int *u_nonce = ((unsigned int *)block + 16 + 3);
    // unsigned int *u_timestamp = ((unsigned int *)block+16+2);

    // Set initial state of sha256.
    sha_initstate((unsigned int *)&state);

    // The block consists of 20 32bit variables, and the first 16 of these make up the first chunk.
    for (n = 0; n < 16; n++)
    {
        chunk[n] = *(block + n);
    }

    // Process it.
    sha_processchunk((unsigned int *)&state, (unsigned int *)&chunk);

#ifdef CBMC
    // set the nonce to a non-deterministic value
    *u_nonce = nondet_uint();

    // make sure the valid nonce is in the range
    // unsigned nonce_start = 497822588 - SATCNF;
    // unsigned nonce_end = 497822588 + SATCNF;
    // __CPROVER_assume(*u_nonce > nonce_start && *u_nonce < nonce_end); // used nonce should stay in the given range
    
__CPROVER_assume(*u_nonce > 1094385912 && *u_nonce < 1094386912);
#endif

    // The last 4 int's go together with some padding to make the second and final chunk.
    for (n = 0; n < 4; n++)
    {
        chunk[n] = *(block + 16 + n);
    }
    for (n = 4; n < 16; n++)
        chunk[n] = pad0[n - 4];

    // And is processed, giving the hash.
    sha_processchunk((unsigned int *)&state, (unsigned int *)&chunk);

    // This hash will be hashed again, so is copied into the chunk buffer, and padding is added.
    for (n = 0; n < 8; n++)
        chunk[n] = state[n];
    for (n = 8; n < 16; n++)
        chunk[n] = pad1[n - 8];

    // State is initialized.
    sha_initstate((unsigned int *)&state);

    // Chunk is processed.
    sha_processchunk((unsigned int *)&state, (unsigned int *)&chunk);

#ifdef CBMC
__CPROVER_assume(
(unsigned char)((state[7] >> 0) & 0xff) == 0x00 &&
(unsigned char)((state[7] >> 8) & 0xff) == 0x00 &&
(unsigned char)((state[7] >> 16) & 0xff) == 0x00 &&
(unsigned char)((state[7] >> 24) & 0xff) == 0x00 &&
(unsigned char)((state[6] >> 0) & 0xff) == 0x00 &&
(unsigned char)((state[6] >> 8) & 0xff) == 0x00 &&
(unsigned char)((state[6] >> 16) & 0xff) == 0x00 &&
(unsigned char)((state[6] >> 24) & 0xff) == 0x00);
int flag = 0;
if ((unsigned char)((state[5] >> 0) & 0xff) != 0x00)
{
   flag = 1;
}
assert(flag == 1);






























   
    
#endif

#ifndef CBMC
    // Printing in reverse, because the hash is a big retarded big endian number in bitcoin.
    for (n = 7; n >= 0; n--)
    {
        printf("%02x-", state[n] & 0xff);
        printf("%02x-", (state[n] >> 8) & 0xff);
        printf("%02x-", (state[n] >> 16) & 0xff);
        printf("%02x-", (state[n] >> 24) & 0xff);
    }
    printf("\n");
#endif

    return (0);
}

unsigned int block_780008[20] = {0x0000a020,
0xbe1e215c,
0xf1768941,
0xc33c4df3,
0x5edb986d,
0x80b0ae1e,
0xcdd30200,
0x00000000,
0x00000000,
0x5e40898a,
0x628606fa,
0x996e2442,
0x3bd23990,
0xca6fea14,
0xbfb5a493,
0x98e086be,
0xe02b3e1f,
0x92d60964,
0xa3890617,
0x413b02ec};
int main(int argc, void *argv[]){verifyhash(&block_780008[0]); return 0;}