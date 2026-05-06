#include "system.h"

static void systick_setup(void) {
    systick_set_frequency(SYSTICK_FREQ, CPU_FREQ);
    systick_counter_enable();
    systick_interrupt_enable();
}

void SYSTEM_Delay(uint64_t millisecond) {
    uint64_t end_time = SYSTEM_Get_Ticks() + millisecond;
    while (SYSTEM_Get_Ticks() < end_time); // Loop
}
