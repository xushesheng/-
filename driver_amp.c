#include <linux/module.h>
#include <linux/platform_device.h>
#include <asm/io.h>
#include <linux/irqchip/arm-gic.h>
#include <asm/smp.h> 
//新加入
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/uio.h>

#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define PL_NET_IP_ADDR       0x38000000  //接收数据IP地址
#define PL_NET_NODE_ID       0x38000004  //接收数据节点号
#define PL_NET_IP_LEN        0x38000008  //接收长度
#define SHARE_MEM_OUT_ADDR   0x38001000  //数据写入首地址
#define SHARE_MEM_IN_ADDR    0x39000000  //数据读取首地址
/* RX: CPU1 -> CPU0 */
#define RX_NET_NODE_ID_ADDR   0x39000004
#define RX_NET_IP_LEN_ADDR    0x39000008
#define RX_RAM_ADDR           0x39001000
#define RX_RAM_MAX_LEN        2048

#define AMP_SGI_TX  15                //CPUO触发的中断号
#define AMP_SGI_RX  14                //CPU1 通知 CPU0
#define MAX_PAYLOAD_SIZE  2048        //写地址空间大小

static struct socket *udp_sock;
/* RX 缓冲（中断 -> workqueue） */
struct amp_rx_packet {
    u32 len;
    __be32 dst_ip;
    u8 data[RX_RAM_MAX_LEN];
};

static struct amp_rx_packet rx_pkt;
static atomic_t rx_pending = ATOMIC_INIT(0);

/* workqueue */
static struct work_struct udp_tx_work;


// 映射共享内存虚拟地址
static void __iomem *pl_ip;           //写入数据IP
static void __iomem *pl_node;         //写入数据节点
static void __iomem *pl_len;          //写入数据的长度
static void __iomem *share_mem_out;   //要写入的数据CPU0 - CPU1
static void __iomem *share_mem_in;    //要读取的数据CPU1 - CPU0
static void __iomem *rx_node_id;      //写入数据节点
static void __iomem *rx_len;          //写入数据的长度
static void __iomem *rx_data;         //写入的数据
/****************
用户态写入write接口
****************/
struct amp_net_msg {
	u32 ip;
	u32 node_id;
	u32 len;
	u8  data[MAX_PAYLOAD_SIZE];
};
static ssize_t amp_write(struct file *file,const char __user *buf,size_t len,loff_t *ppos)
{
	struct amp_net_msg msg;                          //创建写入网络数据结构体 
	if (len < offsetof(struct amp_net_msg, data))    //判断数据是否为空
    return -EINVAL;
	if (copy_from_user(&msg, buf, min(len, sizeof(msg))))
		return -EFAULT;
	if (msg.len > MAX_PAYLOAD_SIZE)
		return -EINVAL;
	/* 写共享内存 */
	if (!share_mem_out || !pl_ip || !pl_node || !pl_len)
	return -ENODEV;	
	memcpy_toio(share_mem_out, msg.data, msg.len);    //写数据
	wmb();// 确保写入对 CPU1 可见（很重要）
	writel(msg.ip, pl_ip);                           //写元信息
	writel(msg.node_id, pl_node);
	wmb();
	writel(msg.len, pl_len);
	wmb();
	/* 写入成功后，再通知 CPU1 */
	gic_raise_softirq_fmsh(1, AMP_SGI_TX);
	pr_info("AMP NET: node=%u len=%u\n", msg.node_id, msg.len);
	return offsetof(struct amp_net_msg, data) + msg.len;
}

/*********************
将驱动函数与系统调用关联起来
**********************/
static const struct file_operations amp_fops = {
	.owner = THIS_MODULE,
	.write = amp_write,//用户态程序使用amp_write函数即可调用驱动模块
};

/*********************
miscdriver注册
**********************/
static struct miscdevice amp_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "amp_ipi",
	.fops  = &amp_fops,
};

/************************
IP节点映射表
************************/
static __be32 nodeid_to_ip(u32 node_id)
{
    u8 ip[4] = {192, 168, 1, 0};

    if (node_id <= 15) {
        ip[3] = 10 + node_id;       // 192.168.1.10 ~ 25
        return htonl(*(u32 *)ip);
    }

    if (node_id == 254) {           // 组播（示例：239.0.0.1）
        ip[0] = 239;
        ip[1] = 0;
        ip[2] = 0;
        ip[3] = 1;
        return htonl(*(u32 *)ip);
    }

    if (node_id == 255) {           // 广播
        ip[3] = 255;
        return htonl(*(u32 *)ip);
    }
    return 0;
}
/****************************
******workqueue 发送函数******
*****************************/
static void udp_tx_work_func(struct work_struct *work)
{
    struct msghdr msg = { 0 };
    struct kvec iov;
    struct sockaddr_in daddr;
    int ret;

    if (!udp_sock)
        goto out;

    if (rx_pkt.len <= 4)
        goto out;

    memset(&daddr, 0, sizeof(daddr));
    daddr.sin_family = AF_INET;
    daddr.sin_addr.s_addr = rx_pkt.dst_ip;
    daddr.sin_port = htons(3408);

    iov.iov_base = rx_pkt.data;
    iov.iov_len  = rx_pkt.len;

    msg.msg_name    = &daddr;
    msg.msg_namelen = sizeof(daddr);

    ret = kernel_sendmsg(udp_sock, &msg, &iov, 1, rx_pkt.len);
    if (ret < 0) {
        pr_err("UDP send failed: %d\n", ret);
    }

out:
    atomic_set(&rx_pending, 0);
}

/* 软中断处理函数：SGI14 */
static void zynq_ipi_handler(int ipinr, void *dev_id)
{
    u32 len;

    /* 如果上一次还没处理完，直接丢弃（防重入） */
    if (atomic_cmpxchg(&rx_pending, 0, 1) != 0)
        return;

    if (!rx_len || !rx_data) {
        atomic_set(&rx_pending, 0);
        return;
    }

    len = readl(rx_len);
    rmb();

    if (len < 4 || len > RX_RAM_MAX_LEN) {
        atomic_set(&rx_pending, 0);
        return;
    }

    /* 读取 dst_ip */
    memcpy_fromio(&rx_pkt.dst_ip, rx_data, 4);

    rx_pkt.len = len - 4;

    /* 读取 UDP payload */
    memcpy_fromio(rx_pkt.data, rx_data + 4, rx_pkt.len);

    /* 调度 workqueue */
    schedule_work(&udp_tx_work);
}




static int zynq_amp_probe(struct platform_device *pdev)
{
	int ret;
	/* ioremap 共享内存 */
	pl_ip         = ioremap_nocache(PL_NET_IP_ADDR, 4);
	pl_node       = ioremap_nocache(PL_NET_NODE_ID, 4);
	pl_len        = ioremap_nocache(PL_NET_IP_LEN, 4);
	share_mem_out = ioremap_nocache(SHARE_MEM_OUT_ADDR, MAX_PAYLOAD_SIZE);
	share_mem_in  = ioremap_nocache(SHARE_MEM_IN_ADDR, 4);
	rx_node_id    = ioremap_nocache(RX_NET_NODE_ID_ADDR, 4);
	rx_len        = ioremap_nocache(RX_NET_IP_LEN_ADDR, 4);
	rx_data       = ioremap_nocache(RX_RAM_ADDR, RX_RAM_MAX_LEN);
	if (!share_mem_in || !pl_ip || !pl_node || !pl_len || !share_mem_out || !rx_node_id || !rx_len || !rx_data)
		return -ENOMEM;

	/* 创建内核 UDP socket */
	ret = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &udp_sock);
	if (ret) {
	    pr_err("UDP socket create failed: %d\n", ret);
	    return ret;
	}
	pr_info("Kernel UDP socket created\n");
	/** 初始化 workqueue **/
	INIT_WORK(&udp_tx_work, udp_tx_work_func);

	/* 注册 miscdevice */
	ret = misc_register(&amp_miscdev);
	if (ret) {
		iounmap(share_mem_out);
		return ret;
	}
	ret = set_ipi_handler(AMP_SGI_RX, zynq_ipi_handler, NULL);  // 注册软中断处理函数，将软中断14绑定到 zynq_ipi_handler 处理函数
	if (ret) {
		pr_err("set_ipi_handler(%d) failed\n", AMP_SGI_RX);
		return ret;
	}
	
	pr_info("SGI%d handler registered\n", AMP_SGI_RX);
	return  0;
}

static int zynq_amp_remove(struct platform_device *pdev)
{
	flush_work(&udp_tx_work);

	/* 1. 清理 SGI */
	clear_ipi_handler(AMP_SGI_RX);
	/* 2. 注销 miscdevice */
	misc_deregister(&amp_miscdev);
	/* 3. 释放共享内存 */
	if (pl_ip)        iounmap(pl_ip);
	if (pl_node)      iounmap(pl_node);
	if (pl_len)       iounmap(pl_len);
	if (share_mem_out) iounmap(share_mem_out);
	if (share_mem_in)  iounmap(share_mem_in);
	if (rx_node_id) iounmap(rx_node_id);
	if (rx_len)  iounmap(rx_len);
	if (rx_data) iounmap(rx_data);
	if (udp_sock) {
    sock_release(udp_sock);
    udp_sock = NULL;
	}

	pr_info("AMP driver removed\n");
	share_mem_out = NULL;
	return 0;
}

/************************
从 device tree 匹配硬件节点
*************************/
static const struct of_device_id amp_of_match[] = {
	{ .compatible = "xlnx,zynq-amp" },
	{ /* Sentinel */ }
};

/***********************
 在 probe() 里：
ioremap
初始化 SGI
初始化共享内存
在 remove() 里释放资源
************************/
static struct platform_driver zynq_amp_test = {
	.driver = {
		.name = "zynq_amp_test",
		.of_match_table = amp_of_match,
	},
	.probe = zynq_amp_probe,
	.remove = zynq_amp_remove,
};

module_platform_driver(zynq_amp_test);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("XuShengQiao");
MODULE_DESCRIPTION("AMP one-way IPC driver");
