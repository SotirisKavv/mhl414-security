#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

typedef struct net_flow
{
  char* src_ip;
  char* dst_ip;
  u_int src_p;
  u_int dst_p;
  char* protocol;

  struct net_flow * next;

} net_flow;

typedef struct tcp_packet
{
  net_flow* flow;
  struct tcphdr * tcp;
  int payload;

  struct tcp_packet * next;

} tcp_packet;

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_tcp_packet(const u_char *, int);
void print_udp_packet(const u_char *, int);
void process_offline(char *);
void pcap_info();

void insert_unique_trans(net_flow *);
net_flow * mk_net_node(char * , char * , u_int , u_int , u_int);
net_flow * insert_trans(net_flow * , net_flow *);
int search_trans(net_flow * , net_flow *);
int netfl_cmp(net_flow *, net_flow *);

tcp_packet * make_tcp_node(net_flow *, struct tcphdr *, int);
tcp_packet * insert_tcp(tcp_packet *, tcp_packet *);
int check_retransmission(tcp_packet *, tcp_packet *);

void usage(void);

struct sockaddr_in source, dest;
net_flow* n_flows = NULL;
tcp_packet* tcp_packs = NULL;
int tcp_bytes = 0, udp_bytes = 0;
int tcp = 0, udp = 0, total = 0, others = 0;
int tcp_fl = 0, udp_fl = 0, total_fl = 0;

//Main
int
main(int argc, char **argv)
{
  int opt;
  char *pcap_filename = NULL;

  while ((opt = getopt(argc, argv, "r:h")) != -1) {
    switch(opt) {
      case 'r':
        pcap_filename = strdup(optarg);
        process_offline(pcap_filename);
        break;
      case 'h':
      default:
        usage();
    }
  }

  free(pcap_filename);

  return 0;
}

//Usage
void
usage()
{
  printf(
    "\n"
    "Usage:\n"
    "    assign_6 -r pcap_filename \n"
    "    assign_6 -h \n"
  );
  printf(
    "\n"
    "Options:\n"
    "-r Packet capture filename (e.g., test.pcap)\n"
    "-h Display help message\n"
  );
  exit(EXIT_FAILURE);
}

/* PCAP Info
 * Prints stats concerning the capture file.
 */
void 
pcap_info()
{
  printf("\nTCP Net Flows: %d\tUDP Net Flows: %d\tTotal Flows: %d\n", tcp_fl, udp_fl, total_fl);
  printf("TCP packets: %d\tUDP packets: %d\tOther Protocol packets: %d\tTotal packets: %d\n", tcp, udp, others, total);
  printf("TCP bytes: %d\tUDP bytes: %d\n", tcp_bytes, udp_bytes);
}

/* Process Offline
 * processes a .pcap file and extracts useful info for each packet.
 */
void
process_offline(char * pcap_file)
{
  pcap_t *handle;

  char err[100];

  printf("Reading file %s for offline packet capturing...\n", pcap_file);
  handle = pcap_open_offline(pcap_file, err);

  if (!handle) {
    fprintf(stderr, "Couldn't open file %s: %s\n", pcap_file, err);
    exit(1);
  }

  pcap_loop(handle, -1, process_packet, NULL);

  pcap_info();

  return;
}

/* Process Packet
 * Processes a packet at a time based on its protocol (TCP/UDP).
 */
void
process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
  int size = header->len;

  //get IP header from packet
  struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
  ++total;
  switch(iph->protocol) { //check protocol
    case 6: //TCP protocol
      ++tcp;
      print_tcp_packet(buffer, size);
      break;
    case 17: //UDP protocol
      ++udp;
      print_udp_packet(buffer, size);
      break;
    default:
      ++others;
      break;
  }
}

/* Print TCP Packet
 * Prints TCP packet's info and decides if it has been retransmited or not.
 */
void 
print_tcp_packet(const u_char *buffer, int len)
{
  unsigned short iphdrlen;
  char * retr = "";

  struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
  iphdrlen = iph->ihl*4;

  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;
	
  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = iph->daddr;

  struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
  int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

  net_flow * trans = mk_net_node(inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr), ntohs(tcph->source), ntohs(tcph->dest), iph->protocol);
  insert_unique_trans(trans);

  tcp_packet * tcp = make_tcp_node(trans, tcph, len-header_size);
  tcp_packs = insert_tcp(tcp_packs, tcp);

  //Check for Retransmission
  if (check_retransmission(tcp_packs->next, tcp)){
    retr = "Retransmitted";
  }

  tcp_bytes += len;

  printf("Src IP (Port): %15s (%5u)\t|| Dst IP (Port): %15s (%5u)  || Protocol: TCP  || Header Size: %5u  || Payload Size: %5u\t|| %s\n",
    inet_ntoa(source.sin_addr), ntohs(tcph->source), inet_ntoa(dest.sin_addr), ntohs(tcph->dest), header_size, len-header_size, retr
  );

  return;
}

/* Print UDP Packet
 * Prints UDP packet's info.
 */
void 
print_udp_packet(const u_char *buffer, int len)
{
  unsigned short iphdrlen;

  struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
  iphdrlen = iph->ihl*4;

  memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

  struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
  int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(udph);

  net_flow * trans = mk_net_node(inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr), ntohs(udph->source), ntohs(udph->dest), iph->protocol);
  insert_unique_trans(trans);

  udp_bytes += len;

  printf("Src IP (Port): %15s (%5u)\t|| Dst IP (Port): %15s (%5u)  || Protocol: UDP  || Header Size: %5u  || Payload Size: %5u\t||\n",
    inet_ntoa(source.sin_addr), ntohs(udph->source), inet_ntoa(dest.sin_addr), ntohs(udph->dest), header_size, len-header_size
  );

  return;
}

/* Insert Unique Transmission
 * Inserts a node to a list, if it is not found in it. Also, updates the corresponding stats.
 */
void
insert_unique_trans(net_flow * trans)
{
  if (!search_trans(n_flows, trans))
  {
    n_flows = insert_trans(n_flows, trans);
    ++total_fl;
    (strcmp(trans->protocol, "TCP")==0) ? ++tcp_fl : ++udp_fl;
  }
}

/* Make NetFlow Node
 * Initializes a node with the attributes set as arguments.
 */
net_flow *
mk_net_node(char * src_ip, char * dst_ip, u_int src_p, u_int dst_p, u_int prot){

  char * protocol = (prot == 6) ? "TCP" : "UDP";

  net_flow* node = (net_flow*)malloc(sizeof(net_flow));
  node->src_ip = src_ip;
  node->dst_ip = dst_ip;
  node->src_p = src_p;
  node->dst_p = dst_p;
  node->protocol = protocol;

  return node;
}

/* Insert Transmission
 * Inserts a node to a list recursively
 */
net_flow *
insert_trans(net_flow * flows, net_flow * fl)
{
  if (flows == NULL) 
    return fl;
  else
    flows->next = insert_trans(flows->next, fl);
  
  return flows;
}

/* Search Transmission
 * Searches for a node in a list recursively. If found, returns 1, else 0.
 */
int
search_trans(net_flow * flows, net_flow * fl)
{
  if (flows == NULL) return 0;

  if (netfl_cmp(flows, fl))
    return 1;
  else
    return search_trans(flows->next, fl);
}

/* Network Flow Compare
 * Returns 1 if flows are the same, else 0.
 */
int
netfl_cmp(net_flow * flow1, net_flow * flow2)
{
  return flow1->dst_p==flow2->dst_p && flow1->src_p==flow2->src_p 
    && strcmp(flow1->dst_ip, flow2->dst_ip)==0 
    && strcmp(flow1->src_ip, flow2->src_ip)==0 
    && strcmp(flow1->protocol, flow2->protocol)==0;
}

/* Make TCP Node
 * Initializes a node with the attributes set as arguments.
 */
tcp_packet *
make_tcp_node(net_flow * flow, struct tcphdr * tcp, int payload)
{
  tcp_packet * packet = (tcp_packet *)malloc(sizeof(tcp_packet));
  packet->flow = flow;
  packet->tcp = tcp;
  packet->payload = payload;
  packet->next = NULL;

  return packet;
}

/* Insert TCP
 * Inserts TCP Transmission on top of list
 */
tcp_packet *
insert_tcp(tcp_packet * packets, tcp_packet * tcp)
{
  if (packets == NULL)
    return tcp;
  else
  {
    tcp->next = packets;
    return tcp;
  }
}

/* Check Retransmission
 * Checks if a packet has been retransmited
 */
int
check_retransmission(tcp_packet * packets, tcp_packet * trans)
{
  if (packets == NULL)
    return 0;
  
  if (netfl_cmp(packets->flow, trans->flow) 
    && packets->tcp->seq-1 != trans->tcp->ack_seq
    && packets->tcp->seq + packets->payload > trans->tcp->seq
    && (trans->tcp->syn == 1 || trans->tcp->fin == 1 || trans->payload > 0))
    return 1;
  else
    return check_retransmission(packets->next, trans);
}