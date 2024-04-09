#include <assert.h>
#include <string.h>

int customStrlen(const char *str)
{
    int length = 0;

    while (str[length] != '\0')
    {
        length++;
    }

    return length;
}

int main()
{
    int len = customStrlen("Hello world");
    
    assert(len == 3);
}