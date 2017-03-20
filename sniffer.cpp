#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <algorithm>
using namespace std;
#include <time.h>
#include "sniffer.h"

void print_app_usage()
{
    cout<<"Usage: sniffer [interface]"<<endl;
    cout<<endl;
    cout<<"Options:"<<endl;
    cout<<"    interface    Listen on <interface> for packets."<<endl;
    cout<<endl;
}

template<typename T>
string i2a(T i)
{
    stringstream ss;
    string si;
    ss<<i;
    ss>>si;
    return si;
}

//{"1.1.1.1->2.2.2.2":{22:1489988774, 80:1489988776} , }
int nr_of_diff_ports = 10;
time_t portscan_timespan = 10;
map<string, map<uint16_t,time_t> > m_ip2ports;
int tcp_clear_packet_MAX = 1024*1024;
int tcp_clear_packet_num = 0;

bool detect_portscan(const u_char *packet)
{
    bool bflag = false;
    string src_ip;
    string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    time_t now = time(NULL);


    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */

    int size_ip;
    int size_tcp;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        cout<<"   * Invalid TCP header length: "<<size_tcp<<" bytes"<<endl;
        return false;
    }

    //!!!
    if(TH_SYN!=tcp->th_flags) return false;

    //clear max
    tcp_clear_packet_num++;
    if(tcp_clear_packet_num>tcp_clear_packet_MAX) {
        m_ip2ports.clear();
        tcp_clear_packet_num = 0;
    }

    //detect statistics
    src_ip = inet_ntoa(ip->ip_src);
    dst_ip = inet_ntoa(ip->ip_dst);
    src_port = ntohs(tcp->th_sport);
    dst_port = ntohs(tcp->th_dport);

    //cout<<src_ip<<":"<<src_port<<"  "<<dst_ip<<":"<<dst_port<<"  "<<now<<endl;
    string ip_src2dst = src_ip+"->"+dst_ip;
    if( m_ip2ports.find(ip_src2dst)==m_ip2ports.end() ) {
        map<uint16_t, time_t> temp;
        m_ip2ports[ip_src2dst] = temp;
    }
    m_ip2ports[ip_src2dst][dst_port] = now;


    if( m_ip2ports[ip_src2dst].size()>nr_of_diff_ports ) {
        for(map<uint16_t, time_t>::iterator it2=m_ip2ports[ip_src2dst].begin(); it2!=m_ip2ports[ip_src2dst].end(); ) {
            if(it2->second+portscan_timespan<time(NULL)) {
                m_ip2ports[ip_src2dst].erase(it2++);
            }
            else it2++ ;
        }

        if( m_ip2ports[ip_src2dst].size()>nr_of_diff_ports ) {
            bflag = true;
            cout<<"detected port_scan: "<<ip_src2dst<<endl;
            string sports_scaned;
            for(map<uint16_t, time_t>::iterator it2=m_ip2ports[ip_src2dst].begin(); it2!=m_ip2ports[ip_src2dst].end(); it2++) {
                sports_scaned += i2a(it2->first)+" ";
            }
            cout<<sports_scaned<<endl;

            m_ip2ports.erase(ip_src2dst);
        }
    }

    return bflag;
}

/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    //cout<<endl;
    //cout<<"Packet number "<<count<<":"<<endl;
    count++;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    if(IPPROTO_TCP==ip->ip_p) {
        detect_portscan(packet);
    }
}

int main(int argc, char* argv[])
{
    char *dev = NULL;                /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_t *handle;                  /* packet capture handle */

    char filter_exp[] = "ip";        /* filter expression [3] */
    struct bpf_program fp;           /* compiled filter program (expression) */
    bpf_u_int32 mask;                /* subnet mask */
    bpf_u_int32 net;                 /* ip */
    int num_packets = 0;             /* number of packets to capture */

    /* check for capture device name on command-line */
    if (argc == 2) {
        dev = argv[1];
    }
    else if (argc > 2) {
        cerr<<"error: unrecognized command-line options"<<endl;
        print_app_usage();
        exit(EXIT_FAILURE);
    }
    else {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            cerr<<"Couldn't find default device: "<<errbuf<<endl;
            exit(EXIT_FAILURE);
        }
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        cerr<<"Couldn't get netmask for device "<<dev<<": "<<errbuf<<endl;
        net = 0;
        mask = 0;
    }

    /* print capture info */
    cout<<"Device: "<<dev<<endl;
    cout<<"Number of packets: "<<num_packets<<endl;
    cout<<"Filter expression: "<<filter_exp<<endl;

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr<<"Couldn't open device "<<dev<<": "<<errbuf<<endl;
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        cerr<<dev<<" is not an Ethernet"<<endl;
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        cerr<<"Couldn't parse filter "<<filter_exp<<": "<<pcap_geterr(handle)<<endl;
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        cerr<<"Couldn't install filter "<<filter_exp<<": "<<pcap_geterr(handle)<<endl;
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    cout<<endl;
    cout<<"Capture complete."<<endl;

    return 0;
}
