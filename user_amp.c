#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stddef.h>  // 包含 offsetof 宏的定义
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define MAX_PAYLOAD_SIZE 2048
#define AMP_DEV "/dev/amp_ipi"
#define CAP_IFACE "eth1"

struct amp_net_msg {
    uint32_t ip;
    uint32_t node_id;
    uint32_t len;
    uint8_t  data[MAX_PAYLOAD_SIZE];
};

int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;

    int amp_fd;
    struct amp_net_msg msg;

    /* 1. 打开 AMP 设备 */
    amp_fd = open(AMP_DEV, O_WRONLY);
    if (amp_fd < 0) {
        perror("open /dev/amp_ipi");
        return 1;
    }

    /* 2. 打开 eth1 抓包 */
    handle = pcap_open_live(CAP_IFACE, 2048, 0, 10, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    /* 3. 只抓 UDP（所有端口） */
    if (pcap_compile(handle, &fp, "udp and (dst host 192.168.1.13 or dst host 192.168.1.12 or dst host 192.168.1.100 or dst host 192.168.1.150 or dst host 192.168.1.200)", 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "pcap filter failed\n");
        return 1;
    }

    printf("Listening on %s, capturing all UDP packets...\n", CAP_IFACE);

    while (1) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int ret = pcap_next_ex(handle, &header, &packet);
        if (ret <= 0)
            continue;

        /* Ethernet以太头 */
        struct ether_header *eth = (struct ether_header *)packet;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP)
            continue;

        /* IP */
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
        if (ip->protocol != IPPROTO_UDP)
            continue;

        int iphdr_len = ip->ihl * 4;

        /* UDP */
        struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + iphdr_len);
        uint16_t udp_len = ntohs(udp->len);
        uint8_t *udp_payload = (uint8_t *)(udp + 1);
        int payload_len = udp_len - sizeof(struct udphdr);

        if (payload_len <= 0 || payload_len > MAX_PAYLOAD_SIZE)
            continue;

        /* 4. 组 AMP 数据 */
        memcpy(msg.data , udp_payload, payload_len);

        msg.len = payload_len;
		msg.ip = 0;
        msg.node_id = 255;                            // 广播 / 测试值

        printf("UDP %d bytes -> AMP \n", payload_len);
        /* 5. 写入 AMP */
        write(amp_fd, &msg, offsetof(struct amp_net_msg, data) + msg.len);

    }

    close(amp_fd);
    pcap_close(handle);
    return 0;
}

