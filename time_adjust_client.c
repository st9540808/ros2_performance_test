#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <linux/ip.h>

#define SERVER_PORT "4950"
#define CLIENT_PORT "4951"
#define SEND_CNT    5

struct TS_t {
    struct timeval aorg, recv, xmit;
};
struct TS_T1_T4 {
    struct timeval T1, T2, T3, T4;
};
int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr,"usage: talker hostname message\n");
        exit(1);
    }

    struct TS_t ts_state;
    struct TS_T1_T4 t1_t4[SEND_CNT];
    // Create server socket
    int serverfd;
    serverfd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    struct sockaddr_in ser_addr;
    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_port = htons(4950);
    ser_addr.sin_addr.s_addr = inet_addr(argv[1]);


    // Create client socket
    int clientfd;
    struct sockaddr_in client_addr;
    int tos = IPTOS_LOWDELAY, timestamp = 1;

    clientfd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (clientfd < 0) {
        perror("Failed to open time server socket");
        return -1;
    }

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(4951);
    if (bind(clientfd, (struct sockaddr *) &client_addr, sizeof(client_addr)) < 0) {
        perror("Failed to bind time server socket");
        close(clientfd);
        return -1;
    }

    if (setsockopt(clientfd, SOL_SOCKET, SO_TIMESTAMP, &timestamp, sizeof(timestamp)) < 0) {
        perror("Failed to enable timestamp support");
        close(clientfd);
        return -1;
    }

    struct timeval drv_ts, *tmp_ts;
    tmp_ts = NULL;
    struct msghdr msgh = {0};
    struct cmsghdr *cmsg = NULL;

    unsigned char buf[128];
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    char aux[128];
    msgh.msg_control = aux;
    msgh.msg_controllen = sizeof(aux);

    for (int i = 0; i < SEND_CNT; i) {
        gettimeofday(&ts_state.aorg, NULL);
        if (sendto(serverfd, &ts_state, sizeof(ts_state), 0, (struct sockaddr *)&ser_addr, sizeof(ser_addr)) == -1) {
            perror("talker: sendto");
            exit(1);
        }

        int rx = recvmsg(clientfd, &msgh, 0);
        if (rx < 0) {
            perror("recvmsg");
            exit(1);
        }

        for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg; cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP) {
                tmp_ts = (struct timeval *) CMSG_DATA(cmsg);
                drv_ts = *tmp_ts;
                break;
            }
        }

        if (tmp_ts == NULL)
            goto AA;

        struct TS_t* ts_from_server;
        ts_from_server = iov.iov_base;
        if (iov.iov_len < sizeof *(ts_from_server))
            printf("weired\n");

        if (ts_state.aorg.tv_sec == (*ts_from_server).aorg.tv_sec) {
            t1_t4[i].T1 = ts_from_server->aorg;
            t1_t4[i].T2 = ts_from_server->recv;
            t1_t4[i].T3 = ts_from_server->xmit;
            t1_t4[i].T4 = drv_ts;
        }

        double T1, T2, T3, T4;

        float offset[SEND_CNT];
        T1 = t1_t4[i].T1.tv_sec + t1_t4[i].T1.tv_usec * 1.0e-6;
        T2 = t1_t4[i].T2.tv_sec + t1_t4[i].T2.tv_usec * 1.0e-6;
        T3 = t1_t4[i].T3.tv_sec + t1_t4[i].T3.tv_usec * 1.0e-6;
        T4 = t1_t4[i].T4.tv_sec + t1_t4[i].T4.tv_usec * 1.0e-6;
        offset[i] = ((T2 - T1) + (T3 - T4))/2;
        printf("offset %d: %f\n",i, offset[i]);
        fflush(stdout);
        usleep(1000 * 3);
    }
    float offset[SEND_CNT];
    double T1, T2, T3, T4;
    for (int i = 0; i < SEND_CNT; i++) {
        printf("%d T1: %d.%d\n",i,t1_t4[i].T1);
        printf("%d T2: %d.%d\n",i,t1_t4[i].T2);
        printf("%d T3: %d.%d\n",i,t1_t4[i].T3);
        printf("%d T4: %d.%d\n",i,t1_t4[i].T4);

        T1 = t1_t4[i].T1.tv_sec + t1_t4[i].T1.tv_usec * 1.0e-6;
        T2 = t1_t4[i].T2.tv_sec + t1_t4[i].T2.tv_usec * 1.0e-6;
        T3 = t1_t4[i].T3.tv_sec + t1_t4[i].T3.tv_usec * 1.0e-6;
        T4 = t1_t4[i].T4.tv_sec + t1_t4[i].T4.tv_usec * 1.0e-6;


        offset[i] = ((T2 - T1) + (T3 - T4))/2;
        printf("T1:%f\n",T1);
    }

    for (int i = 0; i < SEND_CNT; i++) {
        printf("offset %d: %f\n",i, offset[i]);
    }

AA:
    close(clientfd);
    close(serverfd);
    return 0;
}
