#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
//#include <iostream>
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
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n\n", param.dev_, errbuf);
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
			printf("pcap_next_ex return %d(%s)\n\n", res, pcap_geterr(pcap));
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

			printf("%02x",ethernet->ether_shost[i]); // mac source 주소 
			if (i == ETHER_ADDR_LEN -1){
				printf("\n\n");
			}
		}
		printf("destination mac address \n");
		for (int i =0; i <ETHER_ADDR_LEN; i++){
			printf("%02x",ethernet->ether_dhost[i]); // mac destination 주소 
			if (i == ETHER_ADDR_LEN -1){
				printf("\n\n");
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
		printf("%02x \n\n", ntohl(ipv4->ip_src.s_addr));

		printf("destination ip address \n");
		printf("%02x \n\n", ntohl(ipv4->ip_dst.s_addr));



		// ntohs : Network to Host Short (2 byte)
		if (ipv4->ip_p == 6){ // TCP packet만 가져오기 위해서
			printf("<TCP>\n");
			printf("source tcp port\n");
			printf("%02x\n\n",tcp->th_sport);
			printf("destination tcp port\n");
			printf("%02x\n\n",tcp-> th_dport);

		}else{
			printf("UDP 입니다");
		}
		

		//printf("%02x\n",tcp->th_off);
		
		
		// ========================= Print Payload (Data) ==========================
		printf("\n<Payload(Data)> \n");

		uint8_t offset = tcp->th_off ;
		// 빅엔디안으로 변환 하는 과정 추가 
		printf("offset %0x \n",offset);
		
		uint16_t offset_16 = offset << 8;
		uint16_t tmp; 
		tmp = (offset_16 & 0xFF00) >> 8;
		tmp += (offset_16 & 0x000F) <<4;
		tmp +=  (offset_16 & 0x00F0) >> 4;

		tmp = tmp * 4;

		
		// ================================= Payload Data 추가 

		uint8_t hsize = tmp; 
		if (hsize == 20){
			printf("");
		}
		for (uint32_t i = sizeof(*ethernet)+sizeof(*ipv4) + tmp;  i < sizeof(*ethernet)+sizeof(*ipv4) + tmp + 10  && i < header->caplen; i++){
			printf("0x%02x ", packet[i]);
		}
		printf("\n\n");
	
	}

	pcap_close(pcap);
}
