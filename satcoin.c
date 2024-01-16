#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// GLOBAL BARIABLES, FUNCTIONS
// const unsigned int pad0[12] = {
//     0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
//     0x00000000, 0x00000000, 0x00000000, 0x00000280};

const unsigned int pad1[8] = {0b10000000000000000000000000000000, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000,
                              0b00000000000000000000000000000000, 0b00000000000000000000000000000000, 0b00000000000000000000000000000000,
                              0b00000000000000000000000000000000, 0b00000000000000000000001000000000};

unsigned int globalState[8];

#define MAX_NONCE 4294967295

void printHashReverse(unsigned int *state)
{
    printf("REVERSE HASH: \n");
    for (int n = 7; n >= 0; n--)
    {
        if (n == 0)
        {
            printf("%x", state[n]);
        }
        else
        {
            printf("%x-", state[n]);
        }
    }
    printf("\n");
}

void printHashNormalWay(unsigned int *state)
{
    printf("NORMAL WAY HASH: \n");
    for (int n = 0; n < 8; n++)
    {
        if (n == 7)
        {
            printf("%x", state[n]);
        }
        else
        {
            printf("%x-", state[n]);
        }
    }
    printf("\n");
}

int count_bits(int value)
{
    int count = 0;
    value += 1;

    // Count the number of bits by shifting until the value becomes zero
    while (value)
    {
        count++;
        value <<= 1;
    }

    return count;
}

void hexToBinaryAndOverwrite(unsigned int *value)
{
    unsigned int originalValue = *value;
    *value = 0; // Clear the original value

    for (int i = sizeof(unsigned int) * 8 - 1; i >= 0; i--)
    {
        *value |= ((originalValue >> i) & 1u) << (sizeof(unsigned int) * 8 - 1 - i);
    }
}

void hexToBinary(unsigned int value, unsigned int *binaryValue)
{
    *binaryValue = 0; // Clear the binary value

    for (int i = sizeof(unsigned int) * 8 - 1; i >= 0; i--)
    {
        *binaryValue |= ((value >> i) & 1u) << (sizeof(unsigned int) * 8 - 1 - i);
    }
}

unsigned int convertStringToBinary(const char *str)
{
    int total = 0;
    int i = 0;
    while (str[i] != '\0')
    {
        total *= 2;
        if (str[i++] == '1')
        {
            total += 1;
        }
    }
    return total;
}

// SHA 256 IMPLEMENTATION START -----------------------------------------------------------------
const unsigned int sha_h[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

const unsigned int sha_k[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

// Inits SHA256 State
void sha256InitState(unsigned int *state)
{
    for (int i = 0; i < 8; i++)
    {
        state[i] = sha_h[i];
    }
}

// Process one chunk of a message, updating state (which after the last chunk is the hash)
void sha256ProcessChunk(unsigned int *state, unsigned int *chunk)
{
    unsigned int w[64], s0, s1;
    unsigned int a, b, c, d, e, f, g, h;
    unsigned int temp1, temp2, maj, ch, S0, S1;
    int n;

    // Read in chunk. When these 32bit words were read, they should have been taken as big endian.
    for (n = 0; n < 16; n++)
        w[n] = chunk[n];

    // Extend the sixteen 32-bit words into sixty-four 32-bit words - MESSAGE SCHEDULE:
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

    // Main loop - COMPRESSION:
    for (n = 0; n < 64; n++)
    {
        S1 = (e >> 6 | e << (32 - 6)) ^ (e >> 11 | e << (32 - 11)) ^ (e >> 25 | e << (32 - 25));
        ch = (e & f) ^ ((~e) & g);
        temp1 = h + S1 + ch + sha_k[n] + w[n];
        S0 = (a >> 2 | a << (32 - 2)) ^ (a >> 13 | a << (32 - 13)) ^ (a >> 22 | a << (32 - 22));
        maj = (a & b) ^ (a & c) ^ (b & c);
        temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Add this chunk's hash to the result so far - MODIFY FINAL VALUES
    *(state + 0) += a;
    *(state + 1) += b;
    *(state + 2) += c;
    *(state + 3) += d;
    *(state + 4) += e;
    *(state + 5) += f;
    *(state + 6) += g;
    *(state + 7) += h;

    globalState[0] = *(state + 0);
    globalState[1] = *(state + 1);
    globalState[2] = *(state + 2);
    globalState[3] = *(state + 3);
    globalState[4] = *(state + 4);
    globalState[5] = *(state + 5);
    globalState[6] = *(state + 6);
    globalState[7] = *(state + 7);
}

int getNumberOfChunks(int dataLen) {
    int numberOfChunks = 0;
    if (dataLen <= 55)
    {
        return 1;
    } else {
        dataLen -= 56;
        numberOfChunks++;
        while(dataLen >= 0) {
            dataLen -= 64;
            numberOfChunks++;
        }
    }
    return numberOfChunks;
}

int sha256(char *data)
{
    unsigned int state[8];
    unsigned int chunk[16];
    int dataLen = strlen(data);

    int numberOfChunks = getNumberOfChunks(dataLen);
    printf("number of chunks: %d\n", numberOfChunks);

    // Set initial state of sha256.
    sha256InitState(state);

    // This array holds one line (one element) of a chunk. It is used, to build the chunks, and to calculate the values of the chunk
    // Example line (chunk element): 0b11001100 11001100 11001100 11001100
    char line[33];
    // Init the array with default values, and the null terminator
    for (int i = 0; i < 32; i++)
    {
        line[i] = '0';
    }
    line[32] = '\0';
    // Indexes, used for the calculation
    int lineIndex = 0;
    int chunkIndex = 0;
    for (int i = 0; i < dataLen; i++)
    {
        // This holds the i element of the data array in binary form
        char bits[8];
        for (int j = 0; j < 8; j++)
        {
            char c = (data[i] >> j) & 1;
            if (c == 0)
            {
                bits[j] = '0';
            }
            else if (c == 1)
            {
                bits[j] = '1';
            }
        }
        for (int i = 7; i >= 0; i--)
        {
            line[lineIndex++] = bits[i];
        }
        if (lineIndex == 32)
        {
            // printf("binary line: %s\n", line);
            char *end;
            unsigned int part;
            part = strtoul(line, &end, 2);
            chunk[chunkIndex++] = part;
            // chunk[chunkIndex++] = convertStringToBinary(line);

            lineIndex = 0;
            for (int i = 0; i < 32; i++)
            {
                line[i] = '0';
            }
        }
    }

    line[lineIndex++] = '1';
    for (int i = lineIndex; i < 32; i++)
    {
        line[lineIndex++] = '0';
    }
    printf("binary line: %s\n", line);
    char *end;
    unsigned int part;
    part = strtoul(line, &end, 2);
    chunk[chunkIndex++] = part;

    lineIndex = 0;
    for (int i = 0; i < 32; i++)
    {
        line[i] = '0';
    }

    for (int i = chunkIndex; i < 16; i++)
    {
        if (i == 15)
        {
            chunk[i] = dataLen * 8;
        }
        else
        {
            chunk[i] = 0b00000000000000000000000000000000;
        }
    }

    // Process it.
    sha256ProcessChunk((unsigned int *)&state, (unsigned int *)&chunk);

    // print hash.
    printHashNormalWay(state);

    sha256InitState(state);
};
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
    (unsigned char)((state[7] >> 16) & 0xff) == 0x00); //&&
                                                       //(unsigned char)((state[7]>>24) & 0xff) == 0x00);

int flag = 0;
// if((unsigned char)((state[6]) & 0xff) != 0x00) {
if ((unsigned char)((state[7] >> 24) & 0xff) != 0x00)
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

// 0b10000000000000000000000000000000 == 0x80000000 == 2147483648
unsigned int input_block[16] = {
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

unsigned int input_block2[16] = {
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

// for (n = 0; n < 8; n++)
// {
//     chunk[n] = state[n];
// }
// for (n = 8; n < 16; n++)
// {
//     chunk[n] = pad1[n - 8];
// }

// // // State is initialized.
// sha256InitState((unsigned int *)&state);

// // // Chunk is processed.
// sha256ProcessChunk((unsigned int *)&state, (unsigned int *)&chunk);

// // // print hash.
// printHashNormalWay(state);

int main(int argc, void *argv[])
{
    sha256("hello worldddddddddddddddddddddddddddddddddddddddddddddddddd");
    // unsigned long nonce = 0;
    // while (nonce < MAX_NONCE)
    // {
    //     // input_block[15] = nonce;
    //     sha256(&input_block[0]);
    //     char state1[9];
    //     itoa(globalState[0], state1, 16);
    //     if (state1[0] == '0' && state1[1] == '0')
    //     {
    //         assert(0);
    //         break;
    //     }
    //     break;
    //     nonce++;
    // }

    return 0;
}