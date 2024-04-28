#include <stdio.h>
#include <time.h>

// Function to calculate nth Fibonacci number recursively with memoization
unsigned long long fib(int n, unsigned long long memo[])
{
    if (n <= 1)
    {
        return n;
    }
    if (memo[n] != 0)
    {
        return memo[n];
    }
    memo[n] = fib(n - 1, memo) + fib(n - 2, memo);
    return memo[n];
}

int main()
{
    clock_t start_time, end_time;
    double cpu_time_used;

    start_time = clock(); // Record the start time

    const int n = 20000;               // You can adjust the value of n here
    unsigned long long memo[20001]; // Array to store calculated Fibonacci values
    for (int i = 0; i <= n; ++i)
    {
        memo[i] = 0; // Initialize memoization array
    }

    unsigned long long result = fib(n, memo); // Calculate the nth Fibonacci number

    end_time = clock(); // Record the end time

    cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("Fibonacci number at position %d: %llu\n", n, result);
    printf("Time taken: %f seconds\n", cpu_time_used);

    return 0;
}
