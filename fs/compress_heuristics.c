#include <linux/log2.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/highmem.h>

#include "compress.h"

#define BASE_RADIX 10

#define MAX_SYMBOLS 256

#define MAX_SAMPLES 2048

#define MAX_SAMPLES_THRESHOLD 1800 // ~90% of sample size

//#define DEBUG_COMPRESS_HEURISTICS

static long nth_digit(long number, int n)
{
        int i;

        for (i = 1; i < n; i++)
                number /= BASE_RADIX;

        return number % BASE_RADIX;
}

static long n_digits(long number)
{
        int d = 0;

        while (number) {
                d++;
                number /= BASE_RADIX;
        }
        return d;
}

int radix_sort(long array[], size_t nr)
{
        long i, k, d, p, np, n_max = 0;
        long bins[BASE_RADIX];

        long *reorder_array = (long *) kzalloc(nr * sizeof(long), GFP_KERNEL);
        if (!reorder_array)
                return -ENOMEM;

        memset((char *)bins, 0, sizeof(long)* BASE_RADIX);

        // largest number
        for (i = 0; i < nr; i++)
                n_max = n_max < array[i] ? array[i] : n_max;

        np = n_digits(n_max);

        for (p = 1; p <= np; p++) {
                long prev;

                // binning
                for (i = 0; i < nr; i++) {
                        d = nth_digit(array[i], p);
                        BUG_ON (d >= BASE_RADIX);
                        bins[d] += 1;
                        #ifdef DEBUG_COMPRESS_HEURISTICS
                        pr_debug("binning > bins[%ld] :%ld data :%ld\n",
                                   d, bins[d], array[i]);
                        #endif
                }

                // prefix sum
                for (i = 1; i < BASE_RADIX; i++) {
                        bins[i] += bins[i - 1];
                        BUG_ON(bins[i] > nr);
                        #ifdef DEBUG_COMPRESS_HEURISTICS
                        pr_debug ("prefix sum > bins[%ld] :%ld\n", i, bins[i]);
                        #endif
                }

                // rebinning
                for (i = 0, prev = 0; i < BASE_RADIX; i++) {
                        long tmp = bins[i];
                        bins[i] = prev;
                        prev = tmp;
                        #ifdef DEBUG_COMPRESS_HEURISTICS
                        pr_debug ("rebinning > bins[%ld] :%ld\n", i, bins[i]);
                        #endif
                }

                // reorder
                for (i = 0; i < nr; i++) {
                        d = nth_digit(array[i], p);
                        k = bins[d];
                        reorder_array[k] = array[i];
                        #ifdef DEBUG_COMPRESS_HEURISTICS
                        pr_debug ("reordering > bin[%ld] :%ld buf index :%ld data :%ld\n",
                                    d, bins[d], k, array[i]);
                        #endif
                        bins[d] = bins[d] + 1;
                }

                memset((char *) bins, 0, sizeof(long) * BASE_RADIX);

                memcpy((char *)array, (char *)reorder_array, nr * sizeof(long));

                #ifdef DEBUG_COMPRESS_HEURISTICS
                for(i = 0; i < nr; i++)
                        pr_debug("round %ld > [%ld] %ld\n", p, i, array[i]);
                #endif
     }

     kfree(reorder_array);

     #ifdef DEBUG_COMPRESS_HEURISTICS
     for (i = 0; i < nr; i++)
          pr_debug("round %ld\t\t[%ld]\t\t%ld\n", p, i, array[i]);
     #endif

     return 0;
}

static int calculate_symbolset_size(long symbol_table[])
{
        int i, symbols = 0;

        for (i = 0; i < MAX_SYMBOLS; i++) {
                if (symbol_table[i])
                        symbols++;
        }
        return symbols;
}

static int calculate_coreset_size(long symbol_table[])
{
        int i;
        u32 symbols = 0, sum_freq = 0;

        (void) radix_sort(symbol_table, MAX_SYMBOLS);

        for (i = 0; i < MAX_SYMBOLS; i++) {
                if (symbol_table[i]) {
                        symbols++;
                        sum_freq += symbol_table[i];
                        if (sum_freq > MAX_SAMPLES_THRESHOLD)
                                break;
                }
        }
        return symbols;
}

/*
 *  Convert FP operations to integer operations
 *
 *  SE = -P * log (P)
 *     = -F/S * log (F/S)
 *     = F/S * (log(S) - log(F))
 */
static int shannon_entropy(long symbol_table[])
{
        int i;
        long entropy_sum = 0, samples = 0, logF, logS;

        for (i = 0; i < MAX_SYMBOLS; i++) {
                if (symbol_table[i])
                        samples += symbol_table[i];
        }

        logS = ilog2(samples);

        for (i = 0; i < MAX_SYMBOLS; i++) {
                if (symbol_table[i]) {
                        logF = ilog2(symbol_table[i]);
                        entropy_sum += (symbol_table[i] * (logS - logF));
                }
        }

        return entropy_sum/samples;
}

long *prepare_symbol_set(struct page *page)
{
        int i;

        void *addr = NULL;

        long *symbol_table = kzalloc(sizeof(long) * MAX_SYMBOLS, GFP_KERNEL);

        if (!symbol_table)
                return ERR_PTR(-ENOMEM);

        addr = kmap(page);

        for (i = 0; i < MAX_SAMPLES; i++) {
                #ifdef HAVE_PRAND
                off_t off = prandom_u32_max(PAGE_SIZE - 1);
                #else
                off_t off = get_random_int() % PAGE_SIZE;
                #endif
                u8 *byteaddr = (u8 *) addr + off;
                symbol_table[*byteaddr] += 1;
                #ifdef DEBUG_COMPRESS_HEURISTICS
                pr_debug("%s off :%lu :%d\n", __func__, off, *byteaddr);
                #endif
        }

        kunmap(addr);

        return symbol_table;
}

bool can_compress(struct page *page) {
        int ret, symbols;

        bool compress = true;

        long *symbol_table = prepare_symbol_set(page);

        symbols = calculate_symbolset_size(symbol_table);

        ret = calculate_coreset_size(symbol_table);
        if (ret >= NR_SYMBOLS_THRESH) {
                compress = false;
                #ifdef DEBUG_COMPRESS_HEURISTICS
                pr_debug("coreset size :%d/%d\n", ret, symbols);
                #endif
                goto exit;
        }

        ret = shannon_entropy(symbol_table);
        if (ret >= SHANNON_ENTROPY_THRESH) {
                compress = false;
                #ifdef DEBUG_COMPRESS_HEURISTICS
                pr_debug("shannon entropy :%d\n", ret);
                #endif
                goto exit;
        }

exit:
        kfree(symbol_table);
        return compress;
}
