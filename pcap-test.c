#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
//#include <bits/in.h>
// #include "./libnet/include/libnet/libnet-headers.h"
// #define ETHER_ADDR_LEN 6




void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	
	if (argc != 2) {
		usage();
		return false;
	}

	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {

	if(argc != 2)
	{
		usage();
		return -1;
	} // 인자 잘못 입력시 


	if (!parse(&param, argc, argv))
		return -1;

	

	char errbuf[PCAP_ERRBUF_SIZE]; // error buffer 
	
	// 위 함수는 실제 기기를 열어주는 기능
	// pcap_open_live(device, snaplen, PROMISCUOUS, 1000, ebuf); 
	// snaplen : 패킷당 저장할 바이스 수, PROMISUOUS : ( 1 ) 모든 패킷을 받겠다는 의미
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr *ethernet;
		struct libnet_ipv4_hdr *ipv4;
		struct libnet_tcp_hdr * tcp;
		

		const u_char* packet;

		int res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) continue;

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		} //error 
		
		//printf("%u bytes captured\n", header->caplen); // 각 패킷들은 byte 단위 .

		ethernet = (struct libnet_ethernet_hdr *)packet; // packet의 주소를 libnet_ethernet_hdr의 포인터로 
		ipv4 = (struct  libnet_ipv4_hdr*)(packet+sizeof(*ethernet)); // 
		tcp = (struct libnet_tcp_hdr *)(packet+sizeof(*ethernet)+sizeof(*ipv4));


		// #============================== etherent ========================================
		// print scr mac , dst mac
		printf("<Ethernet>\n");
		printf("source mac address\n");
		for(int i=0; i<ETHER_ADDR_LEN; i++){

			printf("%02X",ethernet->ether_shost[i]); // mac source 주소 
			if (i == ETHER_ADDR_LEN -1){
				printf("\n");
			}
		}
		printf("destination mac address \n");
		for (int i =0; i <ETHER_ADDR_LEN; i++){
			printf("%02X",ethernet->ether_dhost[i]); // mac destination 주소 
			if (i == ETHER_ADDR_LEN -1){
				printf("\n");
			}
		}

		//##============================ IPv4 ===================================================
		// print ipv4 protocol
	
		printf("<IPv4>\n");
		u_int8_t ip_type = ipv4 -> ip_p; // TCP 버전 확인  Protocol TCP(6)
		u_int8_t ip_sum  = ipv4 -> ip_sum; // TCP checksum 버전 확인 

		/* TCP 일 때 뽑아야 하는 조건 추가 && Port 번호 추가  */


		// 리틀엔디안으로 구성됨 (4byte)
		printf("source ip address \n");
		printf("%02x \n", ntohl(ipv4->ip_src.s_addr));

		printf("destination ip address \n");
		printf("%02x \n", ntohl(ipv4->ip_dst.s_addr));

		// ## ========================== TCP ===================================================

		// ntohs : Network to Host Short (2 byte)
		printf("source tcp port\n");
		printf("%d\n",ntohs(tcp-> th_sport));

		printf("destination tcp port\n");
		printf("%d\n",ntohs(tcp-> th_dport));


		// TCP 데이터 확인 	TCP 헤더의 길이 : 20btye 


		printf("Payload(Data): \n");
		uint32_t hsize = 20; 
		for (int i = hsize;  i < i + 10 && i <header->caplen; i++){
			printf("0x%02X", packet[i]);
		}
		printf("\n");
	

	}

	pcap_close(pcap);
}
