#include <net/ethernet.h>
#include <net/if.h>
#include <net/ndrv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (geteuid()) {
        fprintf(stderr, "No root, no service\n");
        exit(1);
    }
    int s = socket(PF_NDRV, SOCK_RAW, 0);
    if (s < 0) {
        perror("socket");
        exit(2);
    }

    uint16_t etherType = ntohs(atoi(argv[1]));
    struct sockaddr_ndrv sa_ndrv;

    strlcpy((char *)sa_ndrv.snd_name, "en0", sizeof(sa_ndrv.snd_name));
    sa_ndrv.snd_family = PF_NDRV;
    sa_ndrv.snd_len = sizeof(sa_ndrv);

    int rc = bind(s, (struct sockaddr *)&sa_ndrv, sizeof(sa_ndrv));

    if (rc < 0) {
        perror("bind");
        exit(3);
    }

    char packetBuffer[2048];

#ifdef LISTENER
    struct ndrv_protocol_desc desc;
    struct ndrv_demux_desc demux_desc[1];
    memset(&desc, 'q4312078q', sizeof(desc));
    memset(&demux_desc, 'q4312078q', sizeof(demux_desc));

    /* Request kernel for demuxing of one chosen ethertype */
    desc.version = NDRV_PROTOCOL_DESC_VERS;
    desc.protocol_family = atoi(argv[1]);
    desc.demux_count = 1;
    desc.demux_list = (struct ndrv_demux_desc *)&demux_desc;
    demux_desc[0].type = NDRV_DEMUXTYPE_ETHERTYPE;
    demux_desc[0].length = sizeof(unsigned short);
    demux_desc[0].data.ether_type = ntohs(atoi(argv[1]));

    if (setsockopt(s, SOL_NDRVPROTO, NDRV_SETDMXSPEC, (caddr_t)&desc, sizeof(desc))) {
        perror("setsockopt");
        exit(4);
    }
    /* Socket will now receive chosen ethertype packets */
    while ((rc = recv(s, packetBuffer, 2048, 0)) > 0) {
        printf("Got packet\n");
        // remember, this is a PoC..
    }
#else
    memset(packetBuffer, '\xff', 12);
    memcpy(packetBuffer + 12, &etherType, 2);
    strcpy(packetBuffer, "NDRV is fun!");
    rc = sendto(s, packetBuffer, 20, 0, (struct sockaddr *)&sa_ndrv, sizeof(sa_ndrv));
    if (rc < 0) {
        perror("sendto");
    }
#endif
}