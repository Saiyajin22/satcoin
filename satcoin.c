/*Sat Based Bitcoin mining*/
/*Based on: https://jheusser.github.io/2013/02/03/satcoin.html*/

#include <stdio.h>
#include <stdlib.h>

/*Global variables and constants*/
#define MAX_NONCE 4294967295

// TODO - Check what are these values uses for.
// int bc = 0;
// unsigned int prevtarget = 0;

const unsigned int pad0[12] = {
    0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000280};

const unsigned int pad1[8] = {0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000100};

/*Outdated padding for the double hashing process.
This is only useful if we consider that the double
hashing occurs by the second SHA256 call will process
the first hash as a string value, rather than a hexadecimal value.
By string I mean inputs like this: 152fb5611b8273bd2c292adea87fdea9d4ee86fbc49db9291a3099ed349a2a62
By hex, we can just copy the values from SHA256's state, so: 0x152fb561, then 0x1b8273bd ....
*/
// const unsigned int double_hash_pad[16] = {
//     0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
//     0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000200};

/*Helper functions*/
void printHashNormalWay(unsigned int *state)
{
    printf("NORMAL WAY HASH: ");
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

void printHashBitcoinWaysBeforeByteSwap(unsigned int *state)
{
    printf("BITCOIN WAY HASH BEFORE BYTE SWAP: ");
    for (int i = 0; i < 8; i++)
    {
        printf("%02x-", state[i] & 0xff);
        printf("%02x-", (state[i] >> 8) & 0xff);
        printf("%02x-", (state[i] >> 16) & 0xff);
        if (i == 7)
        {
            printf("%02x", (state[i] >> 24) & 0xff);
        }
        else
        {
            printf("%02x-", (state[i] >> 24) & 0xff);
        }
    }
    printf("\n");
}

void printHashBitcoinWay(unsigned int *state)
{
    printf("BITCOIN WAY HASH: ");
    for (int i = 7; i >= 0; i--)
    {
        printf("%02x-", state[i] & 0xff);
        printf("%02x-", (state[i] >> 8) & 0xff);
        printf("%02x-", (state[i] >> 16) & 0xff);
        if (i == 0)
        {
            printf("%02x", (state[i] >> 24) & 0xff);
        }
        else
        {
            printf("%02x-", (state[i] >> 24) & 0xff);
        }
    }
    printf("\n");

    // unsigned char c1 = (unsigned char)((state[5] >> 0) & 0xff);
    // unsigned char c2 = (unsigned char)((state[5] >> 8) & 0xff);
    // unsigned char c3 = (unsigned char)((state[5] >> 16) & 0xff);
    // unsigned char c4 = (unsigned char)((state[5] >> 24) & 0xff);
    // printf("c1: %d \n", c1);
    // printf("c2: %d \n", c2);
    // printf("c3: %d \n", c3);
    // printf("c4: %d \n", c4);
    // printf("c1hex: %02x \n", c1);
    // printf("c2hex: %02x \n", c2);
    // unsigned char c21 = c2 >> 0 & 0xf;
    // unsigned char c22 = c2 >> 4 & 0xf; // This way we can assume 1 hex digit at a time, instead of 2.
    // printf("c21: %02x \n", c21);
    // printf("c22: %02x \n", c22);
    // unsigned char f0 = 240;
    // unsigned char f = f0 >> 4 & 0xf;
    // unsigned char chex = ((unsigned char)((state[5] >> 8) & 0xff)) >> 4 & 0xf;
    // printf("chex: %02x \n", chex);
    // printf("f: %02x \n", f);
    // printf("comp: %d \n", c2 == 0);
    // printf("c3hex: %02x \n", c3);
    // printf("c4hex: %02x \n", c4);
    // printf("zeroHex: %d \n", (((unsigned char)((state[5] >> 0) & 0xff)) >> 4 & 0xf) == 0x0);
}

char *hashToString(unsigned int *state)
{
    char *result = malloc(65);
    sprintf(result, "%08x%08x%08x%08x%08x%08x%08x%08x",
            state[0], state[1], state[2], state[3],
            state[4], state[5], state[6], state[7]);
    printf("Hash as string: %s\n", result);
    return result;
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

/*SHA256 set initial state with the constant values*/
void sha_initstate(unsigned int *state)
{
    for (int i = 0; i < 8; i++)
    {
        *state = sha_h[i];
        state++;
    }
}

/*Processing one chunk of the message, which updates the state*/
/*Bitcoin uses double hashing*/
/*One chunk is an array with 16 elements. Each element is 4 bytes, overall it's 64 bytes / 512 bits*/
/*When we process the last chunk, then the last 8 bytes / 64 bits of the chunk is not a part of the message itself, it's the message's length encoded.*/
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

    // Add this chunk's hash to the result so far:
    *(state + 0) += a;
    *(state + 1) += b;
    *(state + 2) += c;
    *(state + 3) += d;
    *(state + 4) += e;
    *(state + 5) += f;
    *(state + 6) += g;
    *(state + 7) += h;
}

/*The main method which processes our input.
It Includes double hashing, chunk processing, chunk creating.*/
void verifyhash(unsigned int *block)
{
    unsigned int state[8];
    unsigned int chunk[16];
    int n;
    unsigned int *u_nonce = ((unsigned int *)block + 16 + 3); // Through this pointer, CBMC will modify the input block's last element, which is the nonce.

    sha_initstate((unsigned int *)&state);

    // The block consists of 20  4 byte / 32 bit variables, and the first 16 of these make up the first chunk.
    for (n = 0; n < 16; n++)
    {
        chunk[n] = *(block + n);
    }

    // Process it.
    sha_processchunk((unsigned int *)&state, (unsigned int *)&chunk);

#ifdef CBMC
    // Set the nonce to a non-deterministic value by CBMC's nondet_uint() call
    // We set it after the first chunk procession, because it will affect only the second chunk
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
    /* =============================== CORRECT NONCE: 497822588 ================================== */
    // __CPROVER_assume(*u_nonce > 497822587 && *u_nonce < 497822589); // 1 nonces only
    // __CPROVER_assume(*u_nonce > 497822580 && *u_nonce < 497822590); // 10 nonces
    // __CPROVER_assume(*u_nonce > 497822580 && *u_nonce < 497822680); // 100 nonces
    // __CPROVER_assume(*u_nonce > 497822585 && *u_nonce < 497823585); // 1k
    // __CPROVER_assume(*u_nonce > 497822585 && *u_nonce < 497832585); // 10k
    // __CPROVER_assume(*u_nonce > 497822585 && *u_nonce < 497922585); // 100k

    /* =============================== BLOCK 218430 ============================================== */
    /* =============================== CORRECT NONCE: 4043570730 ================================== */
    // __CPROVER_assume(*u_nonce > 4043570729 && *u_nonce < 4043570731); // 1 nonces only
    // __CPROVER_assume(*u_nonce > 4043570725 && *u_nonce < 4043570735); // 10 nonces
    // __CPROVER_assume(*u_nonce > 4043570650 && *u_nonce < 4043570750); // 100 nonces
    // __CPROVER_assume(*u_nonce > 4043570000 && *u_nonce < 4043571000); // 1k
    // __CPROVER_assume(*u_nonce > 4043570000 && *u_nonce < 4043580000); // 10k
    // __CPROVER_assume(*u_nonce > 4043500000 && *u_nonce < 4043600000); // 100k

    /* =============================== BLOCK 467000 ============================================== */
    /* =============================== CORRECT NONCE: 4286565448 ================================== */
    // __CPROVER_assume(*u_nonce > 4286565447 && *u_nonce < 4286565449); // 1 nonces only
    // __CPROVER_assume(*u_nonce > 4286565440 && *u_nonce < 4286565450); // 10 nonces
    // __CPROVER_assume(*u_nonce > 4286565400 && *u_nonce < 4286565500); // 100 nonces
    // __CPROVER_assume(*u_nonce > 4286565000 && *u_nonce < 4286566000); // 1k

    /* =============================== BLOCK 654000 ============================================== */
    /* =============================== CORRECT NONCE: 2806799514 ================================== */
    // __CPROVER_assume(*u_nonce > 2806799513 && *u_nonce < 2806799515); // 1 nonces only
    // __CPROVER_assume(*u_nonce > 2806799510 && *u_nonce < 2806799520); // 10 nonces
    // __CPROVER_assume(*u_nonce > 2806799500 && *u_nonce < 2806799600); // 100 nonces
    // __CPROVER_assume(*u_nonce > 2806799000 && *u_nonce < 2806800000); // 1k

    /* =============================== BLOCK 780000 ============================================= */
    /* =============================== CORRECT NONCE: 674152640 ================================== */
    // __CPROVER_assume(*u_nonce > 674152639 && *u_nonce < 674152641); // 1 nonces only
    // __CPROVER_assume(*u_nonce > 674152635 && *u_nonce < 674152645); // 10 nonces
    // __CPROVER_assume(*u_nonce > 674152630 && *u_nonce < 674152730); // 100 nonces
    // __CPROVER_assume(*u_nonce > 674152500 && *u_nonce < 674153500); // 1k nonces
    // __CPROVER_assume(*u_nonce > 674150000 && *u_nonce < 674160000); // 10k nonces
    // __CPROVER_assume(*u_nonce > 674100000 && *u_nonce < 674200000); // 100k nonces

    /* =============================== BLOCK 780900 ============================================= */
    /* =============================== CORRECT NONCE: 1261881605 ================================== */
    // __CPROVER_assume(*u_nonce > 1261881604 && *u_nonce < 1261881606); // 1 nonces only
    // __CPROVER_assume(*u_nonce > 1261881600 && *u_nonce < 1261881610); // 10 nonces
    // __CPROVER_assume(*u_nonce > 1261881600 && *u_nonce < 1261881700); // 100 nonces
    __CPROVER_assume(*u_nonce > 1261881000 && *u_nonce < 1261882000); // 1k nonces

#endif // else UNSATCNF
#endif // else SATCNF
#endif // end CBMC

    // Here we process the ramining 4 values of the input block.
    // We use the correct padding for it.
    // This is the 2nd and final chunk, which when processed, will give us the first SHA256 hash.
    for (n = 0; n < 4; n++)
    {
        chunk[n] = *(block + 16 + n);
    }
    for (n = 4; n < 16; n++)
        chunk[n] = pad0[n - 4];

    // Here we process the 2nd and final chunk which gives us the first SHA256 hash.
    sha_processchunk((unsigned int *)&state, (unsigned int *)&chunk);

    /* ================= 2ND HASH / DOUBLE HASHING ================================= */
    // The hash will be hashed again, this will make the double hashing.
    // We copy the hexadecimal values from the state, to the chunk, and add the correct padding to it.
    // Then we will process this chunk, state's values will get process ad hexadecimal values, rather than a string value.
    for (n = 0; n < 8; n++)
        chunk[n] = state[n];
    for (n = 8; n < 16; n++)
        chunk[n] = pad1[n - 8];

    // This is a whole new hash, so we need to reinitialize the state.
    sha_initstate((unsigned int *)&state);

    // We process the the chunk, which will give us the final hash.
    // After this, we will have the correct SHA256 Hash for our input_block, which is Double hashed.
    sha_processchunk((unsigned int *)&state, (unsigned int *)&chunk);

/* ==================== ASSERTION and ASSUMPTIONS ================================= */
/* This is the part Where we assume the number of leading zeros, and make an assertion, which will fail, so CBMC detects the correct nonce */
#ifdef CBMC
    /* =============================== GENESIS BLOCK ============================================= */
    // __CPROVER_assume(
    //     (unsigned char)(state[7] & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 8) & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 16) & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 24) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 0) & 0xff) == 0x00);

    /* =============================== BLOCK 218430 ============================================== */
    // __CPROVER_assume(
    //     (unsigned char)(state[7] & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 8) & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 16) & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 24) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 0) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 8) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 16) & 0xff) == 0x00);

    /* =============================== BLOCK 467000 ============================================== */
    __CPROVER_assume(
        (unsigned char)(state[7] & 0xff) == 0x00 &&
        (unsigned char)((state[7] >> 8) & 0xff) == 0x00 &&
        (unsigned char)((state[7] >> 16) & 0xff) == 0x00 &&
        (unsigned char)((state[7] >> 24) & 0xff) == 0x00 &&
        (unsigned char)((state[6] >> 0) & 0xff) == 0x00 &&
        (unsigned char)((state[6] >> 8) & 0xff) == 0x00 &&
        (unsigned char)((state[6] >> 16) & 0xff) == 0x00 &&
        (unsigned char)((state[6] >> 24) & 0xff) == 0x00 &&
        (((unsigned char)((state[5] >> 0) & 0xff)) >> 4 & 0xf) == 0x0);

    /* =============================== BLOCK 654000 ============================================== */
    // __CPROVER_assume(
    //     (unsigned char)(state[7] & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 8) & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 16) & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 24) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 0) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 8) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 16) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 24) & 0xff) == 0x00 &&
    //     (unsigned char)((state[5] >> 0) & 0xff) == 0x00 &&
    //     (((unsigned char)((state[5] >> 8) & 0xff)) >> 4 & 0xf) == 0x0);

    /* =============================== BLOCK 780000 ============================================= */
    // __CPROVER_assume(
    //     (unsigned char)(state[7] & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 8) & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 16) & 0xff) == 0x00 &&
    //     (unsigned char)((state[7] >> 24) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 0) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 8) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 16) & 0xff) == 0x00 &&
    //     (unsigned char)((state[6] >> 24) & 0xff) == 0x00 &&
    //     (unsigned char)((state[5] >> 0) & 0xff) == 0x00 &&
    //     (unsigned char)((state[5] >> 8) & 0xff) == 0x00);

    /* =============================== BLOCK 780900 ============================================= */
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

    /* ============================= ASSERTION - Modify as needed ==================================================== */
    int flag = 0;
    if ((unsigned char)((state[5] >> 8) & 0xff) == 0x00)
    {
        flag = 1;
    }
    assert(flag == 0);
#endif

#ifndef CBMC
    // Printing hash in normal, convenient way.
    printHashNormalWay(state);

    // Printing in before byte swap - bitcoin way.
    printHashBitcoinWaysBeforeByteSwap(state);

    // Printing in reverse, because the hash is a big retarded big endian number in bitcoin.
    printHashBitcoinWay(state);
#endif
} // end verifyHash

/* Heusser's function - TODO Check what it does*/
// void processblocks(char *filename)
// {
//     FILE *f;
//     char buf[256];
//     unsigned int *bp, *bsize, *block;
//     unsigned int n, t;

//     bp = (unsigned int *)&buf;
//     bsize = bp + 1;
//     block = bp + 2;

//     f = fopen(filename, "rb");

//     while (fread(buf, 1, 88, f) == 88)
//     {
//         // Swap endianess.. I think this is already done in the RPC getwork(), but that must be triple checked.
//         for (n = 0; n < 20; n++)
//         {
//             t = *(block + n);
//             t = (t >> 24) | (t << 24) | ((t & 0x00ff0000) >> 8) | ((t & 0x0000ff00) << 8);
//             *(block + n) = t;
//         }

//         verifyhash(block);

//         bc++;
//         fseek(f, *bsize - 80, SEEK_CUR);
//     }

//     fclose(f);
// }

/* ============================= INPUT BLOCKS ============================================= */
unsigned int genesis_block[20] = {
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
    22223344}; // randomly picked nonce which will be overwritten

unsigned int block_218430[20] = {
    0x01000000,
    0x660675bc,
    0xaf38efda,
    0xc1d8d4f1,
    0xac71425e,
    0x7ee406b7,
    0x55524edb,
    0xe3040000,
    0x00000000,
    0x6b7e2727,
    0x1fc5ae0a,
    0xb735c5d1,
    0x56bdfaf1,
    0xee344164,
    0xf4a9107d,
    0x6cf0411c,
    0xfd6fd7ea,
    0x77740651,
    0xb1a6051a,
    // 0xf103fe2a}; // correct nonce
    0x22223333}; // randomly picked nonce which will be overwritten

unsigned int block_467000[20] = {
    0x04000000,
    0x59136a33,
    0x88d4add3,
    0x9472ab40,
    0x90a03ef2,
    0x372933ca,
    0x3209f000,
    0x00000000,
    0x00000000,
    0x86111669,
    0x262e5ace,
    0xa6b2db34,
    0x0b5da146,
    0x8aa1d3cf,
    0x89b816ce,
    0x809ff141,
    0x978d1974,
    0xa2d61d59,
    0xa7f60118,
    // 0xff7fcc48}; // correct nonce
    0x22223333}; // randomly picked nonce which will be overwritten

unsigned int block_654000[20] = {
    0x00000020,
    0xe2c646aa,
    0xdddee991,
    0x17dece9f,
    0x4aa6b55a,
    0xe9b08338,
    0x2c000200,
    0x00000000,
    0x00000000,
    0x59a77dd7,
    0xbe7408c6,
    0x7f0ef976,
    0xf75dcb27,
    0xf6f8ab78,
    0x802cf7df,
    0x25c36dd4,
    0x15df0d3c,
    0xcd43935f,
    0x4e130e17,
    // 0xa74c5c9a}; // correct nonce
    0x22223333}; // randomly picked nonce which will be overwritten

unsigned int block_780000[20] = {
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
    0x22223333}; // random nonce which will be overwritten

unsigned int block_780900[20] = {
    0x00a05521,
    0x621058fe,
    0xc4bf8557,
    0x617b517f,
    0x26559829,
    0x891e533c,
    0x95590100,
    0x00000000,
    0x00000000,
    0x56ebb725,
    0x35fc21f5,
    0x59cf2dc4,
    0x9470a3cb,
    0xb7f4c3a7,
    0x9572fd38,
    0x24b2f6ca,
    0xe50040fa,
    0xda931164,
    0x81760617,
    // 0x4b36c905}; // correct nonce
    0x22223333}; // random nonce which will be overwritten

int main(int argc, void *argv[])
{
    verifyhash(&block_780900[0]);
    return 0;
}