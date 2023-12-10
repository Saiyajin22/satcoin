int main() {
    unsigned int h = ((0b01101010000010011110011001100111 + 0b01001111010000110100000101010010) % ((2^32) -1));
    printf("h: %d\n", h);

    return 0;
}

void printArray(unsigned int *array)
{
    for (int i = 0; i < 20; ++i)
    {
        printf("%u\n", array[i]);
    }
}