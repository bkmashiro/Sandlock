/*
 * pipes.c - I/O pipe handling
 */

#include "sandlock.h"

void setup_pipes(void) {
    pipe(stdin_pipe);
    pipe(stdout_pipe);
    pipe(stderr_pipe);
}

void child_setup_pipes(void) {
    // Redirect stdin from pipe
    close(stdin_pipe[1]);
    dup2(stdin_pipe[0], STDIN_FILENO);
    close(stdin_pipe[0]);
    
    // Redirect stdout/stderr to pipes
    close(stdout_pipe[0]);
    dup2(stdout_pipe[1], STDOUT_FILENO);
    close(stdout_pipe[1]);
    
    close(stderr_pipe[0]);
    dup2(stderr_pipe[1], STDERR_FILENO);
    close(stderr_pipe[1]);
}

void parent_handle_pipes(void) {
    close(stdin_pipe[0]);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    
    // Close stdin for now
    close(stdin_pipe[1]);
    
    unsigned long total_out = 0;
    unsigned long total_err = 0;
    char buf[4096];
    
    struct pollfd fds[2];
    fds[0].fd = stdout_pipe[0];
    fds[0].events = POLLIN;
    fds[1].fd = stderr_pipe[0];
    fds[1].events = POLLIN;
    
    while (fds[0].fd >= 0 || fds[1].fd >= 0) {
        int ret = poll(fds, 2, 100);
        if (ret <= 0) {
            int status;
            if (waitpid(child_pid, &status, WNOHANG) > 0) break;
            continue;
        }
        
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(stdout_pipe[0], buf, sizeof(buf));
            if (n > 0) {
                if (config.max_output == 0 || total_out < config.max_output) {
                    ssize_t to_write = n;
                    if (config.max_output > 0 && total_out + n > config.max_output) {
                        to_write = config.max_output - total_out;
                    }
                    write(STDOUT_FILENO, buf, to_write);
                    total_out += n;
                }
            }
        }
        if (fds[0].revents & (POLLHUP | POLLERR)) {
            close(stdout_pipe[0]);
            fds[0].fd = -1;
        }
        
        if (fds[1].revents & POLLIN) {
            ssize_t n = read(stderr_pipe[0], buf, sizeof(buf));
            if (n > 0) {
                if (config.max_output == 0 || total_err < config.max_output) {
                    ssize_t to_write = n;
                    if (config.max_output > 0 && total_err + n > config.max_output) {
                        to_write = config.max_output - total_err;
                    }
                    write(STDERR_FILENO, buf, to_write);
                    total_err += n;
                }
            }
        }
        if (fds[1].revents & (POLLHUP | POLLERR)) {
            close(stderr_pipe[0]);
            fds[1].fd = -1;
        }
    }
    
    if (fds[0].fd >= 0) close(stdout_pipe[0]);
    if (fds[1].fd >= 0) close(stderr_pipe[0]);
}
