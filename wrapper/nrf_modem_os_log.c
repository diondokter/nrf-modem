#include <stdio.h>
#include <string.h>
#include <stdarg.h>

void nrf_modem_os_log_wrapped(int level, const char *msg);

void nrf_modem_os_log(int level, const char *fmt, ...)
{
    static char msg[128];
    va_list args;

    // Make sure msg is empty
    memset(msg, 0, sizeof(msg));

    // Format message in buffer
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    // Bring the message into the rust world
    nrf_modem_os_log_wrapped(level, msg);
}
