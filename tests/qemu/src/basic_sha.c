#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include "metal/machine.h"
#include "metal/tty.h"
#include "api/hardware/v0.5/random/hca_trng.h"
#include "api/hardware/v0.5/sifive_hca-0.5.x.h"
#include "api/hardware/hca_utils.h"
#include "api/hardware/hca_macro.h"
#include "unity_fixture.h"
#include "dma_test.h"


//-----------------------------------------------------------------------------
// Constants
//-----------------------------------------------------------------------------

static const uint8_t _TEXT_00[] __attribute__((aligned(sizeof(uint64_t)))) = {
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x08
};

static const uint8_t _TEXT_0A[] __attribute__((aligned(sizeof(uint64_t)))) = {
    0x0A, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x08
};
static const uint8_t _TEXT_HASH_00[] = {
    0x6E, 0x34, 0x0B, 0x9C, 0xFF, 0xB3, 0x7A, 0x98, 0x9C, 0xA5, 0x44, 0xE6,
    0xBB, 0x78, 0x0A, 0x2C, 0x78, 0x90, 0x1D, 0x3F, 0xB3, 0x37, 0x38, 0x76,
    0x85, 0x11, 0xA3, 0x06, 0x17, 0xAF, 0xA0, 0x1D
};

static const uint8_t _TEXT_HASH_0A[] = {
    0x01, 0xBA, 0x47, 0x19, 0xC8, 0x0B, 0x6F, 0xE9, 0x11, 0xB0, 0x91, 0xA7,
    0xC0, 0x51, 0x24, 0xB6, 0x4E, 0xEE, 0xCE, 0x96, 0x4E, 0x09, 0xC0, 0x58,
    0xEF, 0x8F, 0x98, 0x05, 0xDA, 0xCA, 0x54, 0x6B
};

#define SHA256_SIZE (256u/CHAR_BIT)

//-----------------------------------------------------------------------------
// Variables
//-----------------------------------------------------------------------------

static uint8_t _sha2_buf[SHA256_SIZE] ALIGN(sizeof(uint64_t));

//-----------------------------------------------------------------------------
// DMA SHA test implementation
//-----------------------------------------------------------------------------

static void
_hca_sha_get_hash(uint8_t * hash, size_t length)
{
    // hash should be aligned, not checked here
    #if __riscv_xlen >= 64
    size_t size = length/sizeof(uint64_t);
    uint64_t * ptr = (uint64_t *)hash;
    #else
    size_t size = length/sizeof(uint32_t);
    uint32_t * ptr = (uint32_t *)hash;
    #endif
    for(unsigned int ix=0; ix<size; ix++) {
        ptr[size - 1u - ix] =
            #if __riscv_xlen >= 64
            __builtin_bswap64(METAL_REG64(HCA_BASE,
                              METAL_SIFIVE_HCA_HASH+ix*sizeof(uint64_t)));
            #else
            __builtin_bswap32(METAL_REG32(HCA_BASE,
                              METAL_SIFIVE_HCA_HASH+ix*sizeof(uint32_t)));
            #endif
    }
}

static void
_sha_push(const uint8_t * src, size_t length)
{
    const uint8_t * end = src+length;
    while ( src < end ) {
        #if __riscv_xlen >= 64
        if ( !(((uintptr_t)src) & (sizeof(uint64_t)-1u)) &&
                (length >= sizeof(uint64_t))) {
            METAL_REG64(HCA_BASE, METAL_SIFIVE_HCA_FIFO_IN) =
                *(const uint64_t *)src;
            src += sizeof(uint64_t);
            length -= sizeof(uint64_t);
            continue;
        }
        #endif // __riscv_xlen >= 64
        if ( ! (((uintptr_t)src) & (sizeof(uint32_t)-1u)) &&
                (length >= sizeof(uint32_t))) {
            METAL_REG32(HCA_BASE, METAL_SIFIVE_HCA_FIFO_IN) =
                *(const uint32_t *)src;
            src += sizeof(uint32_t);
            length -= sizeof(uint32_t);
            continue;
        }
        if ( ! (((uintptr_t)src) & (sizeof(uint16_t)-1u)) &&
                (length >= sizeof(uint16_t))) {
            METAL_REG16(HCA_BASE, METAL_SIFIVE_HCA_FIFO_IN) =
                *(const uint16_t *)src;
            src += sizeof(uint16_t);
            length -= sizeof(uint16_t);
            continue;
        }
        if ( ! (((uintptr_t)src) & (sizeof(uint8_t)-1u)) ) {
            METAL_REG8(HCA_BASE, METAL_SIFIVE_HCA_FIFO_IN) =
                *(const uint8_t *)src;
            src += sizeof(uint8_t);
            length -= sizeof(uint8_t);
            continue;
        }
    }
}

static void
_test_sha_aligned_poll(uint8_t * hash ALIGN(sizeof(uint64_t)),
                       const uint8_t * buf ALIGN(sizeof(uint64_t)),
                       bool big_endian) {
    uint32_t reg;

    reg = METAL_REG32(HCA_BASE, METAL_SIFIVE_HCA_HCA_REV);
    if ( ! reg ) {
        PRINTF("HCA rev: %08x", reg);
        TEST_FAIL_MESSAGE("HCA rev is nil");
    }

    reg = METAL_REG32(HCA_BASE, METAL_SIFIVE_HCA_SHA_REV);
    if ( ! reg ) {
        PRINTF("SHA rev: %08x", reg);
        TEST_FAIL_MESSAGE("SHA rev is nil");
    }

    // FIFO mode: SHA
    _hca_updreg32(METAL_SIFIVE_HCA_CR, 1,
                  HCA_REGISTER_CR_IFIFOTGT_OFFSET,
                  HCA_REGISTER_CR_IFIFOTGT_MASK);

    // IRQ: not on Crypto done
    _hca_updreg32(METAL_SIFIVE_HCA_CR, 0,
                  HCA_REGISTER_CR_CRYPTODIE_OFFSET,
                  HCA_REGISTER_CR_CRYPTODIE_MASK);
    // IRQ: not on output FIFO not empty
    _hca_updreg32(METAL_SIFIVE_HCA_CR, 0,
                  HCA_REGISTER_CR_OFIFOIE_OFFSET,
                  HCA_REGISTER_CR_OFIFOIE_MASK);
    // IRQ: not on DMA done
    _hca_updreg32(METAL_SIFIVE_HCA_CR, 0,
                  HCA_REGISTER_CR_DMADIE_OFFSET,
                  HCA_REGISTER_CR_DMADIE_MASK);

    // SHA mode: SHA2-256
    _hca_updreg32(METAL_SIFIVE_HCA_SHA_CR, 0x1,
                  HCA_REGISTER_SHA_CR_MODE_OFFSET,
                  HCA_REGISTER_SHA_CR_MODE_MASK);

    if ( _hca_sha_is_busy() ) {
        TEST_FAIL_MESSAGE("SHA HW is busy");
    }

    // sanity check
    uint32_t hca_cr = METAL_REG32(HCA_BASE, METAL_SIFIVE_HCA_CR);
    TEST_ASSERT_EQUAL_MESSAGE(hca_cr & HCA_CR_IFIFO_EMPTY_BIT,
                              HCA_CR_IFIFO_EMPTY_BIT,
                              "FIFO in is not empty");
    TEST_ASSERT_EQUAL_MESSAGE(hca_cr & HCA_CR_IFIFO_FULL_BIT, 0u,
                              "FIFO in is full");

    // endianness mode
    _hca_updreg32(METAL_SIFIVE_HCA_CR, !!big_endian,
                  HCA_REGISTER_CR_ENDIANNESS_OFFSET,
                  HCA_REGISTER_CR_ENDIANNESS_MASK);

    // SHA start
    _hca_updreg32(METAL_SIFIVE_HCA_SHA_CR, 1,
                  HCA_REGISTER_SHA_CR_INIT_OFFSET,
                  HCA_REGISTER_SHA_CR_INIT_MASK);

    const uint64_t * ptr = (const uint64_t *)buf;
    for (unsigned int ix=0u; ix<64u/sizeof(uint64_t); ix++) {
        uint64_t value = *ptr++;
        if ( ! big_endian ) {
            value = __builtin_bswap64(value);
        }
        //PRINTF("Push 0x%016lX", value);
        //DUMP_SHEX("  as bytes: ", (const uint8_t *)&value, sizeof(uint64_t));
        METAL_REG64(HCA_BASE, METAL_SIFIVE_HCA_FIFO_IN) = value;
    }

    while ( _hca_sha_is_busy() ) {
        // busy loop
    }

    uint64_t * phash = (uint64_t *)hash;
    for (unsigned int ix=0; ix<SHA256_SIZE; ix+=sizeof(uint64_t)) {
        uint64_t value = METAL_REG64(HCA_BASE,
            (METAL_SIFIVE_HCA_HASH + SHA256_SIZE - sizeof(uint64_t)) - ix);
        *phash++ = __builtin_bswap64(value);
    }
    // DUMP_SHEX("Hash: ", hash, SHA256_SIZE);

    // be sure to leave the IFIFO empty, or other tests would fail
    // as there is not HCA reset for now, the easiest way is to change the
    // mode. Note that this may not reflect the way the actual HW behaves..
    _hca_updreg32(METAL_SIFIVE_HCA_CR, 0,
                  HCA_REGISTER_CR_IFIFOTGT_OFFSET,
                  HCA_REGISTER_CR_IFIFOTGT_MASK);
    _hca_updreg32(METAL_SIFIVE_HCA_CR, 1,
                  HCA_REGISTER_CR_IFIFOTGT_OFFSET,
                  HCA_REGISTER_CR_IFIFOTGT_MASK);
}


//-----------------------------------------------------------------------------
// Unity tests
//-----------------------------------------------------------------------------

TEST_GROUP(basic_sha_poll);

TEST_SETUP(basic_sha_poll) {}

TEST_TEAR_DOWN(basic_sha_poll) {}

TEST(basic_sha_poll, aligned_00)
{
    memset(_sha2_buf, 0, sizeof(_sha2_buf));
    _test_sha_aligned_poll(_sha2_buf, _TEXT_00, true);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(_TEXT_HASH_00, _sha2_buf,
                                         sizeof(_TEXT_HASH_00),
                                         "SHA256 mismatch (big endian)");
    memset(_sha2_buf, 0, sizeof(_sha2_buf));
    _test_sha_aligned_poll(_sha2_buf, _TEXT_00, false);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(_TEXT_HASH_00, _sha2_buf,
                                        sizeof(_TEXT_HASH_00),
                                        "SHA256 mismatch (little endian)");
}

TEST(basic_sha_poll, aligned_0a)
{
    memset(_sha2_buf, 0, sizeof(_sha2_buf));
    _test_sha_aligned_poll(_sha2_buf, _TEXT_0A, true);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(_TEXT_HASH_0A, _sha2_buf,
                                         sizeof(_TEXT_HASH_0A),
                                         "SHA256 mismatch (big endian)");
    memset(_sha2_buf, 0, sizeof(_sha2_buf));
    _test_sha_aligned_poll(_sha2_buf, _TEXT_0A, false);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(_TEXT_HASH_0A, _sha2_buf,
                                        sizeof(_TEXT_HASH_0A),
                                        "SHA256 mismatch (little endian)");
}

TEST_GROUP_RUNNER(basic_sha_poll)
{
    RUN_TEST_CASE(basic_sha_poll, aligned_00);
    RUN_TEST_CASE(basic_sha_poll, aligned_0a);
}
