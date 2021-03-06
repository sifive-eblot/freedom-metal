/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */
/* ----------------------------------- */
/* ----------------------------------- */

#ifndef METAL_PLATFORM_H
#define METAL_PLATFORM_H

/* From clint@2000000 */
#define METAL_RISCV_CLINT0_2000000_BASE_ADDRESS 33554432UL
#define METAL_RISCV_CLINT0_0_BASE_ADDRESS 33554432UL
#define METAL_RISCV_CLINT0_2000000_SIZE 65536UL
#define METAL_RISCV_CLINT0_0_SIZE 65536UL

#define METAL_RISCV_CLINT0
#define METAL_RISCV_CLINT0_MSIP_BASE 0UL
#define METAL_RISCV_CLINT0_MTIMECMP_BASE 16384UL
#define METAL_RISCV_CLINT0_MTIME 49144UL

/* From interrupt_controller@c000000 */
#define METAL_RISCV_PLIC0_C000000_BASE_ADDRESS 201326592UL
#define METAL_RISCV_PLIC0_0_BASE_ADDRESS 201326592UL
#define METAL_RISCV_PLIC0_C000000_SIZE 67108864UL
#define METAL_RISCV_PLIC0_0_SIZE 67108864UL
#define METAL_RISCV_PLIC0_C000000_RISCV_MAX_PRIORITY 7UL
#define METAL_RISCV_PLIC0_0_RISCV_MAX_PRIORITY 7UL
#define METAL_RISCV_PLIC0_C000000_RISCV_NDEV 55UL
#define METAL_RISCV_PLIC0_0_RISCV_NDEV 55UL

#define METAL_RISCV_PLIC0
#define METAL_RISCV_PLIC0_PRIORITY_BASE 0UL
#define METAL_RISCV_PLIC0_PENDING_BASE 4096UL
#define METAL_RISCV_PLIC0_ENABLE_BASE 8192UL
#define METAL_RISCV_PLIC0_ENABLE_PER_HART 128UL
#define METAL_RISCV_PLIC0_CONTEXT_BASE 2097152UL
#define METAL_RISCV_PLIC0_CONTEXT_PER_HART 4096UL
#define METAL_RISCV_PLIC0_CONTEXT_THRESHOLD 0UL
#define METAL_RISCV_PLIC0_CONTEXT_CLAIM 4UL

/* From prci@10008000 */
#define METAL_SIFIVE_FE310_G000_PRCI_10008000_BASE_ADDRESS 268468224UL
#define METAL_SIFIVE_FE310_G000_PRCI_0_BASE_ADDRESS 268468224UL
#define METAL_SIFIVE_FE310_G000_PRCI_10008000_SIZE 4096UL
#define METAL_SIFIVE_FE310_G000_PRCI_0_SIZE 4096UL

#define METAL_SIFIVE_FE310_G000_PRCI
#define METAL_SIFIVE_FE310_G000_PRCI_HFROSCCFG 0UL
#define METAL_SIFIVE_FE310_G000_PRCI_HFXOSCCFG 4UL
#define METAL_SIFIVE_FE310_G000_PRCI_PLLCFG 8UL
#define METAL_SIFIVE_FE310_G000_PRCI_PLLOUTDIV 12UL

/* From gpio@10012000 */
#define METAL_SIFIVE_GPIO0_10012000_BASE_ADDRESS 268509184UL
#define METAL_SIFIVE_GPIO0_0_BASE_ADDRESS 268509184UL
#define METAL_SIFIVE_GPIO0_10012000_SIZE 4096UL
#define METAL_SIFIVE_GPIO0_0_SIZE 4096UL

#define METAL_SIFIVE_GPIO0
#define METAL_SIFIVE_GPIO0_VALUE 0UL
#define METAL_SIFIVE_GPIO0_INPUT_EN 4UL
#define METAL_SIFIVE_GPIO0_OUTPUT_EN 8UL
#define METAL_SIFIVE_GPIO0_PORT 12UL
#define METAL_SIFIVE_GPIO0_PUE 16UL
#define METAL_SIFIVE_GPIO0_DS 20UL
#define METAL_SIFIVE_GPIO0_RISE_IE 24UL
#define METAL_SIFIVE_GPIO0_RISE_IP 28UL
#define METAL_SIFIVE_GPIO0_FALL_IE 32UL
#define METAL_SIFIVE_GPIO0_FALL_IP 36UL
#define METAL_SIFIVE_GPIO0_HIGH_IE 40UL
#define METAL_SIFIVE_GPIO0_HIGH_IP 44UL
#define METAL_SIFIVE_GPIO0_LOW_IE 48UL
#define METAL_SIFIVE_GPIO0_LOW_IP 52UL
#define METAL_SIFIVE_GPIO0_IOF_EN 56UL
#define METAL_SIFIVE_GPIO0_IOF_SEL 60UL
#define METAL_SIFIVE_GPIO0_OUT_XOR 64UL

/* From spi@10014000 */
#define METAL_SIFIVE_SPI0_10014000_BASE_ADDRESS 268517376UL
#define METAL_SIFIVE_SPI0_0_BASE_ADDRESS 268517376UL
#define METAL_SIFIVE_SPI0_10014000_SIZE 4096UL
#define METAL_SIFIVE_SPI0_0_SIZE 4096UL

#define METAL_SIFIVE_SPI0
#define METAL_SIFIVE_SPI0_SCKDIV 0UL
#define METAL_SIFIVE_SPI0_SCKMODE 4UL
#define METAL_SIFIVE_SPI0_CSID 16UL
#define METAL_SIFIVE_SPI0_CSDEF 20UL
#define METAL_SIFIVE_SPI0_CSMODE 24UL
#define METAL_SIFIVE_SPI0_DELAY0 40UL
#define METAL_SIFIVE_SPI0_DELAY1 44UL
#define METAL_SIFIVE_SPI0_FMT 64UL
#define METAL_SIFIVE_SPI0_TXDATA 72UL
#define METAL_SIFIVE_SPI0_RXDATA 76UL
#define METAL_SIFIVE_SPI0_TXMARK 80UL
#define METAL_SIFIVE_SPI0_RXMARK 84UL
#define METAL_SIFIVE_SPI0_FCTRL 96UL
#define METAL_SIFIVE_SPI0_FFMT 100UL
#define METAL_SIFIVE_SPI0_IE 112UL
#define METAL_SIFIVE_SPI0_IP 116UL

/* From test@12000 */
#define METAL_SIFIVE_TEST0_12000_BASE_ADDRESS 73728UL
#define METAL_SIFIVE_TEST0_0_BASE_ADDRESS 73728UL
#define METAL_SIFIVE_TEST0_12000_SIZE 8192UL
#define METAL_SIFIVE_TEST0_0_SIZE 8192UL

#define METAL_SIFIVE_TEST0
#define METAL_SIFIVE_TEST0_FINISHER_OFFSET 0UL

/* From uart@10013000 */
#define METAL_SIFIVE_UART0_10013000_BASE_ADDRESS 268513280UL
#define METAL_SIFIVE_UART0_0_BASE_ADDRESS 268513280UL
#define METAL_SIFIVE_UART0_10013000_SIZE 4096UL
#define METAL_SIFIVE_UART0_0_SIZE 4096UL

/* From uart@10023000 */
#define METAL_SIFIVE_UART0_10023000_BASE_ADDRESS 268578816UL
#define METAL_SIFIVE_UART0_1_BASE_ADDRESS 268578816UL
#define METAL_SIFIVE_UART0_10023000_SIZE 4096UL
#define METAL_SIFIVE_UART0_1_SIZE 4096UL

#define METAL_SIFIVE_UART0
#define METAL_SIFIVE_UART0_TXDATA 0UL
#define METAL_SIFIVE_UART0_RXDATA 4UL
#define METAL_SIFIVE_UART0_TXCTRL 8UL
#define METAL_SIFIVE_UART0_RXCTRL 12UL
#define METAL_SIFIVE_UART0_IE 16UL
#define METAL_SIFIVE_UART0_IP 20UL
#define METAL_SIFIVE_UART0_DIV 24UL

/* From hca@1007000 */
#define METAL_SIFIVE_HCA_VERSION 1280UL

#define METAL_SIFIVE_HCA_1007000_BASE_ADDRESS 268894208UL
#define METAL_SIFIVE_HCA_0_BASE_ADDRESS 268894208UL
#define METAL_SIFIVE_HCA_1007000_SIZE 4096UL
#define METAL_SIFIVE_HCA_0_SIZE 4096UL

#define METAL_SIFIVE_HCA_CR 0UL
#define METAL_SIFIVE_HCA_AES_CR 16UL
#define METAL_SIFIVE_HCA_AES_ALEN 32UL
#define METAL_SIFIVE_HCA_AES_PDLEN 40UL
#define METAL_SIFIVE_HCA_AES_KEY 48UL
#define METAL_SIFIVE_HCA_AES_INITV 80UL
#define METAL_SIFIVE_HCA_SHA_CR 96UL
#define METAL_SIFIVE_HCA_FIFO_IN 112UL
#define METAL_SIFIVE_HCA_AES_OUT 128UL
#define METAL_SIFIVE_HCA_AES_AUTH 144UL
#define METAL_SIFIVE_HCA_HASH 160UL
#define METAL_SIFIVE_HCA_TRNG_CR 224UL
#define METAL_SIFIVE_HCA_TRNG_SR 228UL
#define METAL_SIFIVE_HCA_TRNG_DATA 232UL
#define METAL_SIFIVE_HCA_TRNG_TRIM 236UL
#define METAL_SIFIVE_HCA_DMA_CR 272UL
#define METAL_SIFIVE_HCA_DMA_LEN 276UL
#define METAL_SIFIVE_HCA_DMA_SRC 280UL
#define METAL_SIFIVE_HCA_DMA_DEST 288UL
#define METAL_SIFIVE_HCA_HCA_REV 512UL
#define METAL_SIFIVE_HCA_AES_REV 516UL
#define METAL_SIFIVE_HCA_SHA_REV 520UL
#define METAL_SIFIVE_HCA_TRNG_REV 524UL

#endif /* METAL_PLATFORM_H*/
