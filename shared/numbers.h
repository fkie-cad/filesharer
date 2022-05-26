#ifndef NUMBERS_H
#define NUMBERS_H

#include <assert.h>
#include <stdint.h>



// from: https://blog.regehr.org/archives/1063

uint8_t rotl8(uint8_t x, uint32_t n)
{
  assert (n<8);
  return (x<<n) | (x>>(-n&7));
}

uint16_t rotl16(uint16_t x, uint32_t n)
{
  assert (n<16);
  return (x<<n) | (x>>(-n&15));
}

uint32_t rotl32(uint32_t x, uint32_t n)
{
  assert (n<32);
  return (x<<n) | (x>>(-n&31));
}

uint64_t rotl64(uint64_t x, uint32_t n)
{
  assert (n<64);
  return (x<<n) | (x>>(-n&63));
}

#endif
