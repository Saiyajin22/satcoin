/*Sat Based Bitcoin mining*/
/*Based on: https://jheusser.github.io/2013/02/03/satcoin.html*/

#include <stdio.h>
#include <stdlib.h>

#define MAX_NONCE 4294967295

int bc = 0;
unsigned int prevtarget = 0;

/*Helper functions*/
void printHashNormalWay(unsigned int *state)
{
    printf("NORMAL WAY HASH: \n");
    for (int n = 0; n < 8; n++)
    {
        if (n == 7)
        {
            printf("%08x", state[n]);
        }
        else
        {
            printf("%08x-", state[n]);
        }
    }
    printf("\n");
}

/*SHA256 constant values for hashing*/
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

unsigned int double_hash_pad[16] = {
    0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000200};

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

#ifdef SATCNF
    // make sure the valid nonce is in the range
    unsigned nonce_start = 497822588 - SATCNF;
    unsigned nonce_end = 497822588 + SATCNF;
    __CPROVER_assume(*u_nonce > nonce_start && *u_nonce < nonce_end); // used nonce should stay in the given range
#else
#ifdef UNSATCNF
    // make sure the valid nonce is not in the range
    unsigned nonce_start = 497822588;
    unsigned nonce_end = nonce_start + UNSATCNF + UNSATCNF;
    __CPROVER_assume(*u_nonce > nonce_start && *u_nonce < nonce_end); // used nonce should stay in the given range
#else

    /* =============================== GENESIS BLOCK ============================================= */
    //__CPROVER_assume(*u_nonce > 0 && *u_nonce < 10);
    __CPROVER_assume(*u_nonce > 497822587 && *u_nonce < 497822589); // 1 nonces only
                                                                    //__CPROVER_assume(*u_nonce > 497822585 && *u_nonce < 497823585); // 1k
                                                                    //__CPROVER_assume(*u_nonce > 497822585 && *u_nonce < 497832585); // 10k
                                                                    //__CPROVER_assume(*u_nonce > 497822585 && *u_nonce < 497922585); // 100k
                                                                    /* =============================== GENESIS BLOCK ============================================= */
                                                                    /* =============================== BLOCK 218430 ============================================== */
                                                                    //__CPROVER_assume(*u_nonce > 4043570728 && *u_nonce < 4043570731);
                                                                    /* =============================== BLOCK 218430 ============================================== */

#endif // else UNSATCNF
#endif // else SATCNF
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

    // char *result = malloc(65);
    // sprintf(result, "%08x%08x%08x%08x%08x%08x%08x%08x",
    //         state[0], state[1], state[2], state[3],
    //         state[4], state[5], state[6], state[7]);
    // printf("first hash: %s\n", result);

    // char temp[5];
    // int tempCounter = 0;
    // int chunkCounter = 0;
    // // Fill chunk correctly with the previous hash, to make the second hash.
    // for (int i = 0; i < 64; i++)
    // {
    //     temp[tempCounter] = result[i];
    //     if (tempCounter == 3)
    //     {
    //         char *endptr;
    //         long decimalNumber = strtol(temp, &endptr, 16);
    //         chunk[chunkCounter++] = decimalNumber;
    //         tempCounter = 0;
    //     }
    //     else
    //     {
    //         tempCounter++;
    //     }
    // }

    // This hash will be hashed again, so is copied into the chunk buffer, and padding is added.
    for (n = 0; n < 8; n++)
        chunk[n] = state[n];
    for (n = 8; n < 16; n++)
        chunk[n] = pad1[n - 8];

    // Second hash
    // State is initialized.
    sha_initstate((unsigned int *)&state);

    // Chunk is processed.
    sha_processchunk((unsigned int *)&state, (unsigned int *)&chunk);

    // for (int i = 0; i < 16; i++)
    // {
    //     chunk[i] = double_hash_pad[i];
    // }

    // sha_processchunk((unsigned int *)&state, (unsigned int *)&chunk);

#ifdef CBMC
    /* =============================== GENESIS BLOCK ============================================= */
    // CBMCs view on state: 0a8ce26f72b3f1b646a2a6c14ff763ae65831e939c085ae1 0019d668 00 00 00 00
    // this is before byteswap.
    //
    // encode structure of hash below target with leading zeros
    //
    __CPROVER_assume(
        (unsigned char)(state[7] & 0xff) == 0x00 &&
        (unsigned char)((state[7] >> 8) & 0xff) == 0x00 &&
        (unsigned char)((state[7] >> 16) & 0xff) == 0x00 &&
        (unsigned char)((state[7] >> 24) & 0xff) == 0x00 &&
        (unsigned char)((state[6] >> 0) & 0xff) == 0x00 &&
        (unsigned char)((state[6] >> 8) & 0xff) == 0x00 &&
        (unsigned char)((state[6] >> 16) & 0xff) == 0x00 &&
        (unsigned char)((state[6] >> 24) & 0xff) == 0x00 &&
        (unsigned char)((state[5] >> 0) & 0xff) == 0x00 &&
        (unsigned char)((state[5] >> 8) & 0xff) == 0x00);

    int flag = 0;
    // if((unsigned char)((state[6]) & 0xff) != 0x00) {
    if ((unsigned char)((state[5] >> 8) & 0xff) != 0x00)
    {
        flag = 1;
    }
    // counterexample to this will contain an additional leading 0 in the hash which makes it below target
    assert(flag == 1);
    /* =============================== GENESIS BLOCK ============================================= */
    /* =============================== BLOCK 218430 ============================================== */
    // 72d4ef030000b7fba3287cb2be97273002a5b3ffd3c19f3d3e-00 00 00-00 00 00 00
    /*__CPROVER_assume(
       (unsigned char)(state[7] & 0xff) == 0x00 &&
       (unsigned char)((state[7]>>8) & 0xff)  == 0x00 &&
       (unsigned char)((state[7]>>16) & 0xff) == 0x00 &&
       (unsigned char)((state[7]>>24) & 0xff) == 0x00 &&
       (unsigned char)((state[6]>>8) & 0xff) == 0x00 &&
       (unsigned char)((state[6]>>16) & 0xff) == 0x00);
     //  (unsigned char)((state[6]>>24) & 0xff) == 0x00);

    int flag = 0;
    if((unsigned char)((state[6]>>24) & 0xff) > 0x5a) {
       flag = 1;
    }
    assert(flag == 1);*/
    /* =============================== BLOCK 218430 ============================================== */
    /* =============================== BLOCK X      ============================================== */
    /* Target here is hex(0x0b1eff * 2**(8*(0x17 - 3))) == 386604799 -> 0x170b1eff */
    /*__CPROVER_assume(
       (unsigned char)(state[7] & 0xff) == 0x00 &&
       (unsigned char)((state[7]>>8) & 0xff)  == 0x00 &&
       (unsigned char)((state[7]>>16) & 0xff) == 0x00 &&
       (unsigned char)((state[7]>>24) & 0xff) == 0x00 &&
       (unsigned char)(state[6] & 0xff) == 0x00 &&
       (unsigned char)((state[6]>>8) & 0xff) == 0x00 &&
       (unsigned char)((state[6]>>16) & 0xff) == 0x00 &&
       (unsigned char)((state[6]>>24) & 0xff) == 0x00 &&
       (unsigned char)(state[5] & 0xff) == 0x00);

    int flag = 0;
    if((unsigned char)((state[5]>>8) & 0xff) > 0x0b) {
       flag = 1;
    }
    assert(flag == 1);*/
    /* =============================== BLOCK X      ============================================== */
#endif

#ifndef CBMC
    // Printing in reverse, because the hash is a big retarded big endian number in bitcoin.
    printHashNormalWay(state);
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

void processblocks(char *filename)
{
    FILE *f;
    char buf[256];
    unsigned int *bp, *bsize, *block;
    unsigned int n, t;

    bp = (unsigned int *)&buf;
    bsize = bp + 1;
    block = bp + 2;

    f = fopen(filename, "rb");

    while (fread(buf, 1, 88, f) == 88)
    {
        // Swap endianess.. I think this is already done in the RPC getwork(), but that must be triple checked.
        for (n = 0; n < 20; n++)
        {
            t = *(block + n);
            t = (t >> 24) | (t << 24) | ((t & 0x00ff0000) >> 8) | ((t & 0x0000ff00) << 8);
            *(block + n) = t;
        }

        verifyhash(block);

        bc++;
        fseek(f, *bsize - 80, SEEK_CUR);
    }

    fclose(f);
}

unsigned int genesis_input_block[20] = {
    16777216,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1000599037,
    2054886066,
    2059873342,
    1735823201,
    2143820739,
    2290766130,
    983546026,
    1260281418,
    699096905,
    4294901789,
    // 497822588}; // correct nonce
250508269}; // randomly picked nonce which will be overwritten

unsigned int input_block_example[20] = {
    16777216,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1000599037,
    2054886066,
    2059873342,
    1735823201,
    2143820739,
    2290766130,
    983546026,
    1260281418,
    699096905,
    4294901789,
    // 497822588}; // correct nonce
    250508269};

// 1 element if 4 bytes, 1 hexadecimal character is 4 bits
unsigned int block_780000[20] = {
    0x201b2000, // version field - GOOD
    0x00000000, // beginning of prev hash - GOOD
    0x00000000,
    0x00063a84,
    0x0d1ae5a1,
    0x090da46e,
    0x1ae749bf,
    0x668ba9f7,
    0xb2a30efe, // end of prev hash - GOOD
    0x3ff040ab, // start of merkle root - GOOD
    0xd19b0675,
    0xcb65c47b,
    0x8069908f,
    0x87a4d128,
    0xd9e60a31,
    0x79e9d294,
    0xe87e94d6,  // end of merkle root - GOOD
    0xbc1b0964,  // timestamp -
    0x170689a3,  // bits - GOOD
    0xc0c02e28}; // correct nonce - GOOD
                 // 250508269}; // randomly picked nonce which will be overwritten

// Hex representation of block 780000
// 201b2000000000000000000000063a840d1ae5a1090da46e1ae749bf668ba9f7b2a30efe3ff040abd19b0675cb65c47b8069908f87a4d128d9e60a3179e9d294e87e94d6c74c9046170689a3c0c02e28
// 201b2000000000000000000000063a840d1ae5a1090da46e1ae749bf668ba9f7b2a30efe3ff040abd19b0675cb65c47b8069908f87a4d128d9e60a3179e9d294e87e94d67cc40964170689a3c0c02e28

unsigned int block_780000_from_api[20] = {
    0x00201b20,
    0xfe0ea3b2,
    0xf7a98b66,
    0xbf49e71a,
    0x6ea40d09,
    0xa1e51a0d,
    0x843a0600,
    0x00000000,
    0x00000000,
    0xd6947ee8,
    0x94d2e979,
    0x310ae6d9,
    0x28d1a487,
    0x8f906980,
    0x7bc465cb,
    0x75069bd1,
    0xab40f03f,
    0x7cc40964,
    0xa3890617,
    // 0x282ec0c0}; // correct nonce
    0x22222222}; // random nonce which will be overwritten

// representation of: helloworlddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
unsigned int input_block_ex[20] = {0b01101000011001010110110001101100, 0b01101111011101110110111101110010, 0b01101100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100, 0b01100100011001000110010001100100};
// c05d8c587992cc1e025bb37a6284a6f1e68fcd6420dd5c33a5d5c5023f49f73e

unsigned int input_block_helloworld[16] = {
    0b01101000011001010110110001101100,
    0b01101111001000000111011101101111,
    0b01110010011011000110010010000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000001011000};

unsigned int input_block_helloworld_doublehash[16] = {
    0b10111001010011010010011110111001, // Binary representation of: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 + padding
    0b10010011010011010011111000001000, // All chars should be separately encoded based on their ascii code's binary repr
    0b10100101001011100101001011010111,
    0b11011010011111011010101111111010,
    0b11000100100001001110111111100011,
    0b01111010010100111000000011101110,
    0b10010000100010001111011110101100,
    0b11100010111011111100110111101001,
    0b10000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000000000000,
    0b00000000000000000000000100000000};

// 201b2000000000000000000000063a840d1ae5a1090da46e1ae749bf668ba9f7b2a30efe3ff040abd19b0675cb65c47b8069908f87a4d128d9e60a3179e9d294e87e94d6c74c9046170689a3c0c02e28

// genesis block hash splitted
// 01000000000000000000000000000000
// 00000000000000000000000000000000
// 000000003BA3EDFD7A7B12B27AC72C3E
// 67768F617FC81BC3888A51323A9FB8AA
// 4B1E5E4A29AB5F49FFFF001D1DAC2B7C

// genesis block hash one line
// 0100000000000000000000000000000000000000000000000000000000000000000000003BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4A29AB5F49FFFF001D1DAC2B7C

/*unsigned int input_block[20] = {
 16777216,

 // prev block
 1711699388,
 2939744218,
 3252212977,
 2893103710,
 2128873143,
 1431457499,
 3808690176,
 0,

 // merkle
 1803429671,
 533048842,
 3073754577,
 1455291121,
 3996402020,
 4104720509,
 1827684636,
 4251965418,

 // time, bits, nonce
 2004092497, 2980447514,// 1
 4043570730
}; */

int main(int argc, void *argv[])
{
    verifyhash(&block_780000_from_api[0]);
    return 0;
}
