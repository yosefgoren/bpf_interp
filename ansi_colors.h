#ifndef __ANSI_COLORS_H__
#define __ANSI_COLORS_H__

// Reset / default
#define ANSI_RESET        "\033[0m"
#define ANSI_WHITE_RAW    "\033[0m"  // alias

// Regular colors
#define ANSI_BLACK_RAW    "\033[0;30m"
#define ANSI_RED_RAW      "\033[0;31m"
#define ANSI_GREEN_RAW    "\033[0;32m"
#define ANSI_YELLOW_RAW   "\033[0;33m"
#define ANSI_BLUE_RAW     "\033[0;34m"
#define ANSI_MAGENTA_RAW  "\033[0;35m"
#define ANSI_CYAN_RAW     "\033[0;36m"
#define ANSI_WHITE_RAW2   "\033[0;37m"  // regular white (dim)

// Bright colors (bold)
#define ANSI_BBLACK_RAW    "\033[1;30m"
#define ANSI_BRED_RAW      "\033[1;31m"
#define ANSI_BGREEN_RAW    "\033[1;32m"
#define ANSI_BYELLOW_RAW   "\033[1;33m"
#define ANSI_BBLUE_RAW     "\033[1;34m"
#define ANSI_BMAGENTA_RAW  "\033[1;35m"
#define ANSI_BCYAN_RAW     "\033[1;36m"
#define ANSI_BWHITE_RAW    "\033[1;37m"

// Text styles
#define ANSI_BOLD_RAW       "\033[1m"
#define ANSI_DIM_RAW        "\033[2m"
#define ANSI_UNDERLINE_RAW  "\033[4m"
#define ANSI_BLINK_RAW      "\033[5m"
#define ANSI_REVERSE_RAW    "\033[7m"
#define ANSI_HIDDEN_RAW     "\033[8m"

// Background colors
#define ANSI_BG_BLACK_RAW    "\033[40m"
#define ANSI_BG_RED_RAW      "\033[41m"
#define ANSI_BG_GREEN_RAW    "\033[42m"
#define ANSI_BG_YELLOW_RAW   "\033[43m"
#define ANSI_BG_BLUE_RAW     "\033[44m"
#define ANSI_BG_MAGENTA_RAW  "\033[45m"
#define ANSI_BG_CYAN_RAW     "\033[46m"
#define ANSI_BG_WHITE_RAW    "\033[47m"

// Bright background colors
#define ANSI_BG_BBLACK_RAW    "\033[100m"
#define ANSI_BG_BRED_RAW      "\033[101m"
#define ANSI_BG_BGREEN_RAW    "\033[102m"
#define ANSI_BG_BYELLOW_RAW   "\033[103m"
#define ANSI_BG_BBLUE_RAW     "\033[104m"
#define ANSI_BG_BMAGENTA_RAW  "\033[105m"
#define ANSI_BG_BCYAN_RAW     "\033[106m"
#define ANSI_BG_BWHITE_RAW    "\033[107m"

// Wrappers (automatically reset to default)
#define ANSI_WRAP(color, s) color s ANSI_RESET

#define ANSI_RED_WRAP(s)      ANSI_WRAP(ANSI_RED_RAW, s)
#define ANSI_GREEN_WRAP(s)    ANSI_WRAP(ANSI_GREEN_RAW, s)
#define ANSI_YELLOW_WRAP(s)   ANSI_WRAP(ANSI_YELLOW_RAW, s)
#define ANSI_BLUE_WRAP(s)     ANSI_WRAP(ANSI_BLUE_RAW, s)
#define ANSI_MAGENTA_WRAP(s)  ANSI_WRAP(ANSI_MAGENTA_RAW, s)
#define ANSI_CYAN_WRAP(s)     ANSI_WRAP(ANSI_CYAN_RAW, s)
#define ANSI_WHITE_WRAP(s)    ANSI_WRAP(ANSI_WHITE_RAW2, s)

#define ANSI_BRED_WRAP(s)      ANSI_WRAP(ANSI_BRED_RAW, s)
#define ANSI_BGREEN_WRAP(s)    ANSI_WRAP(ANSI_BGREEN_RAW, s)
#define ANSI_BYELLOW_WRAP(s)   ANSI_WRAP(ANSI_BYELLOW_RAW, s)
#define ANSI_BBLUE_WRAP(s)     ANSI_WRAP(ANSI_BBLUE_RAW, s)
#define ANSI_BMAGENTA_WRAP(s)  ANSI_WRAP(ANSI_BMAGENTA_RAW, s)
#define ANSI_BCYAN_WRAP(s)     ANSI_WRAP(ANSI_BCYAN_RAW, s)
#define ANSI_BWHITE_WRAP(s)    ANSI_WRAP(ANSI_BWHITE_RAW, s)

#endif // __ANSI_COLORS_H__
