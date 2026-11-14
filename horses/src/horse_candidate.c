#include <stdint.h>
#include <stddef.h>

/* validated fnv1a */
uint32_t fnv1a(const uint8_t *data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= 16777619u; }
    return h;
}

/* validated digit_sum_u32 */
int digit_sum_u32(uint32_t x) {
    int s = 0;
    do { s += (int)(x % 10u); x /= 10u; } while (x != 0u);
    return s;
}