#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/byteorder/generic.h>

#define MY_MODULE_NAME "traffic_changer"

MODULE_LICENSE("GPL");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Roman Ponomarenko <r.e.p@yandex.ru>");

struct nf_hook_ops my_hook;

unsigned int hook_function(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned i;
	struct udphdr *data;
	struct iphdr *ip;

	pr_info("[%s] len: %d datalen: %d\n", MY_MODULE_NAME, skb->len,
			skb->data_len);
	pr_info("[%s] transport_header: %hd\n", MY_MODULE_NAME,
			skb->transport_header);
	pr_info("[%s] network_header: %hd\n", MY_MODULE_NAME,
			skb->network_header);
	pr_info("[%s] mac_header: %hd\n", MY_MODULE_NAME,
			skb->inner_mac_header);
	pr_info("[%s] sk_buff: %p\n", MY_MODULE_NAME, skb);
	pr_info("[%s] head: %p\n", MY_MODULE_NAME, skb->head);
	pr_info("[%s] data: %p\n", MY_MODULE_NAME, skb->data);
	pr_info("[%s] tail: %u\n", MY_MODULE_NAME, skb->tail);
	pr_info("[%s] end: %u\n", MY_MODULE_NAME, skb->end);
	//pr_info("[%s] \n", MY_MODULE_NAME);
	if(skb->len > 9 && skb->data[9] == 17) {
		ip = (struct iphdr*)skb->data;
		pr_info("[%s] %08x %08x %hhu %hu\n", MY_MODULE_NAME,
				ntohl(ip->saddr), ntohl(ip->daddr),
				ip->protocol, ntohs(ip->tot_len));

		data = (struct udphdr*)(skb->head + skb->transport_header);
		pr_info("[%s] source: %hu\n", MY_MODULE_NAME,
				ntohs(data->source));
		pr_info("[%s] dest: %hu\n", MY_MODULE_NAME , ntohs(data->dest));
		pr_info("[%s] len: %hu\n", MY_MODULE_NAME , ntohs(data->len));
		pr_info("[%s] check: %hu\n", MY_MODULE_NAME ,
				ntohs(data->check));
		if(ntohs(data->dest) == 13000) {
			*(int*)&(skb->data[28]) = 0;
			*(int*)&(skb->data[29]) = 0;
		}
	}
	return NF_ACCEPT;
}

static int __init tc_init(void)
{
	pr_info("[%s] init\n", MY_MODULE_NAME);
	my_hook.hook = hook_function;
	my_hook.pf = PF_INET;
	my_hook.hooknum = NF_INET_PRE_ROUTING;
	my_hook.priority = NF_IP_PRI_LAST;
	if(nf_register_hook(&my_hook) != 0)
		pr_err("[%s] error nf_register_hook\n", MY_MODULE_NAME);
	return 0;
}

static void __exit tc_exit(void)
{
	pr_info("[%s] exit sk_buff's size: %ld\n", MY_MODULE_NAME, sizeof(struct sk_buff));
	nf_unregister_hook(&my_hook);
}

module_init(tc_init);
module_exit(tc_exit);
