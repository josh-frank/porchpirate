// porchpirate - world's smallest packet sniffer (Linux only)
// cc -Os porchpirate.c -o porchpirate && sudo ./porchpirate | grep 443
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

int main(void) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) return perror("socket (try sudo)"), 1;
    unsigned char b[65536], *t;
    char a[INET6_ADDRSTRLEN], z[INET6_ADDRSTRLEN], f[8];
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (ssize_t n; (n = recv(s, b, sizeof b, 0)) > 0; ) {
        int type = ntohs(((struct ethhdr *)b)->h_proto), pr, off = ETH_HLEN;
        if (type == ETH_P_IP && n >= off + 20) {
            struct iphdr *ip = (void *)(b + off);
            inet_ntop(AF_INET, &ip->saddr, a, sizeof a);
            inet_ntop(AF_INET, &ip->daddr, z, sizeof z);
            pr = ip->protocol, off += ip->ihl * 4;
        } else if (type == ETH_P_IPV6 && n >= off + 40) {
            struct ip6_hdr *ip = (void *)(b + off);
            inet_ntop(AF_INET6, &ip->ip6_src, a, sizeof a);
            inet_ntop(AF_INET6, &ip->ip6_dst, z, sizeof z);
            pr = ip->ip6_nxt, off += 40;
        } else {
            printf("ETH 0x%04x %zd\n", type, n);
            continue;
        }
        t = b + off;
        if (pr == 6 && n >= off + 14) {
            char *p = f;
            for (int i = 0; i < 6; i++)
                if (t[13] & 1 << i) *p++ = "FSRPAU"[i];
            *p = 0;
            printf("TCP %s:%d > %s:%d [%s] %zd\n", a, t[0] << 8 | t[1],
                   z, t[2] << 8 | t[3], f, n);
        } else if (pr == 17 && n >= off + 8)
            printf("UDP %s:%d > %s:%d %zd\n", a, t[0] << 8 | t[1],
                   z, t[2] << 8 | t[3], n);
        else
            printf("%s %s > %s %zd\n", pr == 1 || pr == 58 ? "ICMP" : "IP", a, z, n);
    }
    return 0;
}
