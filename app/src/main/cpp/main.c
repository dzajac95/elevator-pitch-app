/*******************************************************************************************
*
*   raylib [core] example - Basic window
*
*   Welcome to raylib!
*
*   To test examples, just press Shift+F10 for Android Studio.
*
*   raylib official webpage: www.raylib.com
*
*   Enjoy using raylib. :)
*
*   Example licensed under an unmodified zlib/libpng license, which is an OSI-certified,
*   BSD-like license that allows static linking with closed source software
*
*   Copyright (c) 2013-2023 Ramon Santamaria (@raysan5) and reviewed by Victor Le Juez
*
********************************************************************************************/

#include <arpa/inet.h>
#include <bits/signal_types.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <android/log.h>

#include "raylib.h"
#include "raymath.h"
#include "raymob.h" // This header can replace 'raylib.h' and includes additional functions related to Android.

#include "dns_task.h"

#define MY_LOG_TAG "UR_MOM"

#define LOG_INFO(...) do { __android_log_print(ANDROID_LOG_INFO, MY_LOG_TAG, __VA_ARGS__); } while(0)
#define LOG_ERR(...) do { __android_log_print(ANDROID_LOG_ERROR, MY_LOG_TAG, __VA_ARGS__); } while(0)
#define LOG_DEBUG(...) do { __android_log_print(ANDROID_LOG_DEBUG, MY_LOG_TAG, __VA_ARGS__); } while(0)

#define FONT_SIZE 36
#define FONT_SPACING 2.0f

enum conn_state {
    RESOLVING,
    START_CONNECT,
    CONNECTING,
    CONNECTED,
    CONN_ERR,
};

enum conn_err {
    ERR_DNS_FAILED,
    ERR_CONN_REFUSED,
    ERR_CONN_TIMEOUT,
    ERR_SOCKET_FAIL,
};

typedef struct {
    Rectangle bounds;
    Color fg;
    Color bg;
    char *text;
    bool active;
} button_t;

// Global state
static Vector2 screen_dim;
static Font font = {0};
enum conn_state c_state = RESOLVING;
enum conn_err c_error = 0;


static Rectangle RecScreenToPixel(Rectangle rec)
{
    return CLITERAL(Rectangle) {
        .x = rec.x * screen_dim.x,
        .y = rec.y * screen_dim.y,
        .width = rec.width * screen_dim.x,
        .height = rec.height * screen_dim.y
    };
}

static bool button(button_t *b) {
    Vector3 bg_hsv = ColorToHSV(b->bg);
    bool within_bounds = CheckCollisionPointRec(GetMousePosition(), RecScreenToPixel(b->bounds));
    if (within_bounds && IsMouseButtonDown(0) && b->active) {
        bg_hsv.z *= 0.9;
    }
    DrawRectangleRounded(RecScreenToPixel(b->bounds), 0.25f, 12, ColorFromHSV(bg_hsv.x, bg_hsv.y, bg_hsv.z));

    Vector2 text_size = Vector2Divide(MeasureTextEx(font, b->text, FONT_SIZE, FONT_SPACING), screen_dim);
    Vector2 text_pos = {
        .x = b->bounds.x + b->bounds.width/2-text_size.x/2,
        .y = b->bounds.y + b->bounds.height/2-text_size.y/2
    };
    DrawTextEx(font, b->text, Vector2Multiply(text_pos, screen_dim), FONT_SIZE, FONT_SPACING, b->fg);
    if (within_bounds && IsMouseButtonPressed(0)) {
        return true;
    } else {
        return false;
    }
}

static bool up_button() {
    bool active = c_state == CONNECTED;
    const Vector2 size = {
        .x = 0.4f,
        .y = 0.1f,
    };
    const Rectangle bounds = {
        .x = 0.5f-size.x/2,
        .y = 0.2f,
        .width = size.x,
        .height = size.y
    };
    Color bg = active ? BLUE : GRAY;
    button_t butt = {
        bounds,
        WHITE,
        bg,
        "Up",
        active,
    };

    return button(&butt);
}

static bool stop_button() {
    bool active = c_state == CONNECTED;
    const Vector2 size = {
        .x = 0.4f,
        .y = 0.1f,
    };
    const Rectangle bounds = {
        .x = 0.5f-size.x/2,
        .y = 0.315f,
        .width = size.x,
        .height = size.y
    };
    Color bg = active ? BLUE : GRAY;
    button_t butt = {
        bounds,
        WHITE,
        bg,
        "Stop",
        active,
    };

    return button(&butt);
}

static bool down_button() {
    bool active = c_state == CONNECTED;
    const Vector2 size = {
        .x = 0.4f,
        .y = 0.1f,
    };
    const Rectangle bounds = {
        .x = 0.5f-size.x/2,
        .y = 0.430f,
        .width = size.x,
        .height = size.y
    };
    Color bg = active ? BLUE : GRAY;
    button_t butt = {
        bounds,
        WHITE,
        bg,
        "Down",
        active,
    };

    return button(&butt);
}

sig_atomic_t dns_done = 0;
void dns_done_cb(void)
{
    dns_done = 1;
}


void socket_init(int *fd)
{
    *fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*fd < 0) {
        LOG_ERR("Failed to create socket: %s", strerror(errno));
        exit(1);
    }
    int opt = 1;
    setsockopt(*fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    if (fcntl(*fd, F_SETFL, fcntl(*fd, F_GETFL) | O_NONBLOCK) != 0) {
        LOG_ERR("Failed to set O_NONBLOCK on the socket!");
        exit(1);
    }
}

//------------------------------------------------------------------------------------
// Program main entry point
//------------------------------------------------------------------------------------
int main(void)
{
    // Initialization
    //--------------------------------------------------------------------------------------
    SetConfigFlags(FLAG_MSAA_4X_HINT);
    InitWindow(0, 0, "raylib [core] example - basic window");
    SetTargetFPS(60);               // Set our game to run at 60 frames-per-second
    font = GetFontDefault();
    screen_dim = CLITERAL(Vector2) {GetScreenWidth(), GetScreenHeight()};
    //--------------------------------------------------------------------------------------

    static const char *up = "up";
    static const char *stop = "stop";
    static const char *down = "down";
    Rectangle status_rec = {
        .x = fmaxf(0.05f*screen_dim.x, 0.05f*screen_dim.y),
        .y = fmaxf(0.05f*screen_dim.x, 0.05f*screen_dim.y),
        .width = 64,
        .height = 64,
    };
    Color status_color = WHITE;

    if (!dns_task_start()) {
        exit(1);
    }
    dns_res_t dns_result;
    dns_task_submit_query("elevator.local", dns_done_cb, &dns_result);
    int sock;
    socket_init(&sock);
    struct pollfd pfd = {
        .fd = sock,
        .events = POLLOUT,
    };

    // Main game loop
    while (!WindowShouldClose())    // Detect window close button or ESC key
    {

        switch (c_state) {
            case RESOLVING:
                status_color = YELLOW;
                if (dns_done == 1) {
                    LOG_INFO("DNS Task Done!\n");
                    if (dns_result.res < 0) {
                        LOG_ERR("DNS Task Failed :(");
                        c_error = ERR_DNS_FAILED;
                        c_state = CONN_ERR;
                    } else {
                        LOG_INFO("Got IP: %s", inet_ntoa(dns_result.addr.sin_addr));
                        c_state = START_CONNECT;
                    }
                    dns_done = 0;
                }
                break;
            case START_CONNECT:
                status_color = ORANGE;
                dns_result.addr.sin_port = htons(6969);
                int ret = connect(sock, (struct sockaddr*)&dns_result.addr, sizeof(dns_result.addr));
                int err = errno;
                if (ret == 0) {
                    LOG_INFO("Successfully connected to device!");
                    c_state = CONNECTED;
                } else {
                    if (err == EINPROGRESS) {
                        LOG_INFO("Awaiting connection.");
                        c_state = CONNECTING;
                    } else {
                        LOG_ERR("Unexpected error ocurred: %s", strerror(errno));
                        c_error = ERR_CONN_REFUSED;
                        c_state = CONN_ERR;
                    }
                }
                break;
            case CONNECTING:
                status_color = ORANGE;
                // polling
                if (poll(&pfd, 1, 0) > 0 && pfd.revents & POLLOUT) {
                    LOG_INFO("Successfully connected, socket is ready for writing!");
                    c_state = CONNECTED;
                }
                break;
            case CONNECTED:
                status_color = GREEN;
                break;
            case CONN_ERR:
                status_color = RED;
                break;
        }

        // Draw
        //----------------------------------------------------------------------------------
        BeginDrawing();

        ClearBackground(RAYWHITE);
        DrawRectangleRec(status_rec, status_color);

        int ret;
        if (up_button()) {
            LOG_INFO("Up!");
            ret = write(sock, up, strlen(up));
        }
        if (stop_button()) {
            LOG_INFO("Stop!");
            ret = write(sock, stop, strlen(stop));
        }
        if (down_button()) {
            LOG_INFO("Down!");
            ret = write(sock, down, strlen(down));
        }
        if (ret < 0) {
            LOG_INFO("Error writing to socket: %s", strerror(errno));
        }

        EndDrawing();
        //----------------------------------------------------------------------------------
    }

    // De-Initialization
    //--------------------------------------------------------------------------------------
    CloseWindow();        // Close window and OpenGL context
    shutdown(sock, SHUT_RDWR);
    close(sock);
    dns_task_shutdown();
    //--------------------------------------------------------------------------------------

    return 0;
}
