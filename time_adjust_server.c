#include <linux/net_tstamp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <linux/ip.h>
#define MYPORT "4950"
#define CLIENT_PORT "4951"
#define RECV_CNT 5000


struct TS_t {
    struct timeval aorg, recv, xmit;
};

int main(int argc, char** argv)
{
    struct TS_t ts_state;

    // Create server socket
    int sockfd;
    struct sockaddr_in addr;
    int tos = IPTOS_LOWDELAY, timestamp = 1;

    sockfd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd < 0) {
        perror("Failed to open time server socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4950);
    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Failed to bind time server socket");
        close(sockfd);
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMP, &timestamp, sizeof(timestamp)) < 0) {
        perror("Failed to enable timestamp support");
        close(sockfd);
        return -1;
    }

    // Create client socket
    int clientfd;
    clientfd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    struct sockaddr_in addr_client;
    memset(&addr_client, 0, sizeof(addr_client));
    addr_client.sin_family = AF_INET;
    addr_client.sin_port = htons(4951);
    addr_client.sin_addr.s_addr = inet_addr(argv[1]);

    // Extract control message from received packet.
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

    for (int i = 0; i < RECV_CNT; i++) {
        int rx = recvmsg(sockfd, &msgh, 0);
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
        struct TS_t* ts_from_client;
        ts_from_client = iov.iov_base;
        if (iov.iov_len < sizeof * (ts_from_client))
            printf("weired\n");
        ts_state = *ts_from_client;
        if (tmp_ts == NULL)
            goto AA;

        gettimeofday(&ts_state.xmit, NULL);
        ts_state.recv = drv_ts;

        if (sendto(clientfd, &ts_state, sizeof(ts_state), 0, (struct sockaddr *)&addr_client, sizeof(addr_client)) == -1) {
            perror("talker: sendto");
            exit(1);
        }

        printf("%d xmit \"%d.%d \" \n", i, ts_state.xmit.tv_sec, ts_state.xmit.tv_usec);
        printf("%d recv \"%d.%d \" \n", i, drv_ts.tv_sec, drv_ts.tv_usec);
        printf("%d aorg \"%d.%d \" \n\n", i, ts_state.aorg.tv_sec, ts_state.aorg.tv_usec);

    }

AA:


    close(sockfd);
    return 0;
}
