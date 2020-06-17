/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */
/* ----------------------------------- */
/* ----------------------------------- */

#ifndef METAL_PLATFORM_H
#define METAL_PLATFORM_H

/* From subsystem_pbus_clock */
#define METAL_FIXED_CLOCK__CLOCK_FREQUENCY 32500000UL

#define METAL_FIXED_CLOCK

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
#define METAL_RISCV_PLIC0_C000000_RISCV_NDEV 33UL
#define METAL_RISCV_PLIC0_0_RISCV_NDEV 33UL

#define METAL_RISCV_PLIC0
#define METAL_RISCV_PLIC0_PRIORITY_BASE 0UL
#define METAL_RISCV_PLIC0_PENDING_BASE 4096UL
#define METAL_RISCV_PLIC0_ENABLE_BASE 8192UL
#define METAL_RISCV_PLIC0_ENABLE_PER_HART 128UL
#define METAL_RISCV_PLIC0_CONTEXT_BASE 2097152UL
#define METAL_RISCV_PLIC0_CONTEXT_PER_HART 4096UL
#define METAL_RISCV_PLIC0_CONTEXT_THRESHOLD 0UL
#define METAL_RISCV_PLIC0_CONTEXT_CLAIM 4UL

/* From error_device@3000 */
#define METAL_SIFIVE_ERROR0_3000_BASE_ADDRESS 12288UL
#define METAL_SIFIVE_ERROR0_0_BASE_ADDRESS 12288UL
#define METAL_SIFIVE_ERROR0_3000_SIZE 4096UL
#define METAL_SIFIVE_ERROR0_0_SIZE 4096UL

#define METAL_SIFIVE_ERROR0

/* From global_external_interrupts */

#define METAL_SIFIVE_GLOBAL_EXTERNAL_INTERRUPTS0

/* From gpio@20002000 */
#define METAL_SIFIVE_GPIO0_20002000_BASE_ADDRESS 536879104UL
#define METAL_SIFIVE_GPIO0_0_BASE_ADDRESS 536879104UL
#define METAL_SIFIVE_GPIO0_20002000_SIZE 4096UL
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

/* From local_external_interrupts_0 */

#define METAL_SIFIVE_LOCAL_EXTERNAL_INTERRUPTS0

/* From pwm@20005000 */
#define METAL_SIFIVE_PWM0_20005000_BASE_ADDRESS 536891392UL
#define METAL_SIFIVE_PWM0_0_BASE_ADDRESS 536891392UL
#define METAL_SIFIVE_PWM0_20005000_SIZE 4096UL
#define METAL_SIFIVE_PWM0_0_SIZE 4096UL

#define METAL_SIFIVE_PWM0
#define METAL_SIFIVE_PWM0_PWMCFG 0UL
#define METAL_SIFIVE_PWM0_PWMCOUNT 8UL
#define METAL_SIFIVE_PWM0_PWMS 16UL
#define METAL_SIFIVE_PWM0_PWMCMP0 32UL
#define METAL_SIFIVE_PWM0_PWMCMP1 36UL
#define METAL_SIFIVE_PWM0_PWMCMP2 40UL
#define METAL_SIFIVE_PWM0_PWMCMP3 44UL

/* From spi@20004000 */
#define METAL_SIFIVE_SPI0_20004000_BASE_ADDRESS 536887296UL
#define METAL_SIFIVE_SPI0_0_BASE_ADDRESS 536887296UL
#define METAL_SIFIVE_SPI0_20004000_SIZE 4096UL
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

/* From teststatus@4000 */
#define METAL_SIFIVE_TEST0_4000_BASE_ADDRESS 16384UL
#define METAL_SIFIVE_TEST0_0_BASE_ADDRESS 16384UL
#define METAL_SIFIVE_TEST0_4000_SIZE 4096UL
#define METAL_SIFIVE_TEST0_0_SIZE 4096UL

#define METAL_SIFIVE_TEST0
#define METAL_SIFIVE_TEST0_FINISHER_OFFSET 0UL

/* From serial@20000000 */
#define METAL_SIFIVE_UART0_20000000_BASE_ADDRESS 536870912UL
#define METAL_SIFIVE_UART0_0_BASE_ADDRESS 536870912UL
#define METAL_SIFIVE_UART0_20000000_SIZE 4096UL
#define METAL_SIFIVE_UART0_0_SIZE 4096UL

#define METAL_SIFIVE_UART0
#define METAL_SIFIVE_UART0_TXDATA 0UL
#define METAL_SIFIVE_UART0_RXDATA 4UL
#define METAL_SIFIVE_UART0_TXCTRL 8UL
#define METAL_SIFIVE_UART0_RXCTRL 12UL
#define METAL_SIFIVE_UART0_IE 16UL
#define METAL_SIFIVE_UART0_IP 20UL
#define METAL_SIFIVE_UART0_DIV 24UL

/* From hca@20000 */
#define METAL_SIFIVE_HCA_VERSION 1283UL

#define METAL_SIFIVE_HCA_20000_BASE_ADDRESS 131072UL
#define METAL_SIFIVE_HCA_0_BASE_ADDRESS 131072UL
#define METAL_SIFIVE_HCA_20000_SIZE 4096UL
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
#define METAL_SIFIVE_HCA_DMA_DEST 284UL
#define METAL_SIFIVE_HCA_HCA_REV 512UL
#define METAL_SIFIVE_HCA_AES_REV 516UL
#define METAL_SIFIVE_HCA_SHA_REV 520UL
#define METAL_SIFIVE_HCA_TRNG_REV 524UL

#endif /* METAL_PLATFORM_H*/