#include <stdio.h>
#include <sys/types.h>
#include<string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<arpa/inet.h>
#include<netinet/tcp.h>
#include <linux/igmp.h>
#include <unistd.h>


/*
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 iphdr reference - http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/structiphdr.html
 tcphdr reference - http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/structtcphdr.html
 udphdr reference - http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/structudphdr.html
 icmphdr reference - https://www.cymru.com/Documents/ip_icmp.h
 igmphdr reference - http://cinnabar.sosdg.org/~qiyong/qxr/linux/source/include/uapi/linux/igmp.h#L300
 */

//int that get data from socket
int rawData;
//struct to store source and destination IP adresses
struct sockaddr_in src, dest;
//number of packets collected
int packetNum=0, tcpNum=0, udpNum=0, icmpNum=0, igmpNum=0;

//ip data
struct ipOut {
    unsigned int ipVer;
    unsigned int headerDWORDS;
    unsigned int headerBytes;
    unsigned int typeOfService;
    unsigned int ipLength;
    unsigned int ident;
    unsigned int ttl;
    unsigned int protocolNum;
    unsigned int checkSum;
    unsigned int protocol;
};
//ip addresses 
struct ipAddr{
    char srcIP[16];
    char destIP[16];
};
//tcp data
struct tcpOut{
    unsigned int srcPort;
    unsigned int destPort;
    unsigned int sequenceNum;
    unsigned int acknoledgeNum;
    unsigned int headerLengthDWORDS;
    unsigned int headerLengthBytes;
    unsigned int urgentFlag;
    unsigned int acknoledgeFlag;
    unsigned int pushFlag;
    unsigned int resetFlag;
    unsigned int syncFlag;
    unsigned int finishFlag;
    unsigned int windowNum;
    unsigned int checkSum;
    unsigned int urgentPointer;

};
//udp data
struct udpOut{
    unsigned int srcPort;
    unsigned int destPort;
    unsigned int length;
    unsigned int checkSum;
};
//icmp data
struct icmpOut{
    unsigned int type;
    unsigned int code;
    unsigned int checkSum;
    char msg[100];
};
//igmp data
struct igmpOut{
    unsigned int type;
    unsigned int code;
    unsigned int checkSum;
    unsigned int group;
};
//hexidecimal data for hex dump
struct hexOut{
    unsigned char *hexBuff;
    int size;
};

/*strcut pointerrs declaration
 * for memory allocation*/
struct ipOut *ipHeadr = NULL;
struct ipAddr *addrHeadr = NULL;
struct hexOut *hexHeadr = NULL;
struct icmpOut *icmpHeadr = NULL;
struct igmpOut *igmpHeadr = NULL;
struct tcpOut *tcpHeadr = NULL;
struct udpOut *udpHeadr = NULL;

void gettingPacket(unsigned char* , int);
void tcpPacketOutput(unsigned char*, int);
void udpPacketOutput(unsigned char*, int);
int ipHeaderOutput(unsigned char*, int);
void icmpOutput(unsigned char * buff, int data);
void igmpOutput(unsigned char * buff, int data);
void hexDataOut(unsigned char * buff, int data);
int  kbhit(void);
void printPackets(int hexPrint, int beginning, int end);
void enterCommand();


int main() {
    printf("Print help to get the command list \n");
    enterCommand();
    //memory allocation itself
    ipHeadr = malloc(sizeof(*ipHeadr));
    addrHeadr = malloc(sizeof(*addrHeadr));
    hexHeadr = malloc(sizeof(*hexHeadr));
    icmpHeadr = malloc(sizeof(*icmpHeadr));
    igmpHeadr = malloc(sizeof(*igmpHeadr));
    tcpHeadr = malloc(sizeof(*tcpHeadr));
    udpHeadr = malloc(sizeof(*udpHeadr));

    struct sockaddr saddr;
    //the buffer data from socket
    unsigned char *buff = malloc(65536);

    //socket creation
    int sock = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if (sock < 0){
        printf ("Error creating socket");
        return 1;
    }

    while (!kbhit()){
        int saddrLength = sizeof saddr;
        //capturing data from socket to buffer
        rawData = recvfrom(sock, buff, 65536, 0, &saddr, &saddrLength);
        //printf("raw data %d\n", rawData);
        if(rawData <0 )
        {
            //errorMsg = "Failed to get packets";
            printf("Failed to get packets\n");
            return 1;
        }
        gettingPacket(buff, rawData);
        printf("Packet captured: %d\n", packetNum);
    }
    
    printf("Stopped\n");
    main();
    return 0;
}

void enterCommand(){
    char command[15];
    scanf("%s", command);

        if(strcmp(command, "help")==0){
            printf("\n------HELP------\n\n");
            printf("start - start the packet sniffer(second time running start would continue previous progress)\n");
            printf("\nprint - print the data sniffed \n");
            printf("\nprintEnd - print the data sniffed up to certain value at the end \n");
            printf("\nprintBeginning - print the data sniffed up to certain value at the beginnig\n");
            printf("\nexit - to exit the program \n");
            printf("\n----------------\n\n");
            enterCommand();
        }

        if(strcmp(command, "start")==0){
            printf("Starting...\n");
            printf("Enter any key to stop...\n");
        }

        if(strcmp(command, "print")==0){
            char tempState[3];
            printf("Do you want to print Hexdump?(enter yes or no)\n");
            scanf("%s", tempState);
            if(strcmp(tempState, "yes")==0){
                printf("Printing packets\n");
                printPackets(1, 0, packetNum);
            }
            if(strcmp(tempState, "no")==0){
                printf("Printing packets\n");
                printPackets(0, 0, packetNum);
            }
            if(strcmp(tempState, "yes")!=0 && strcmp(tempState, "no")!=0){
                printf("Returning to default, please enter correct data\n");
            }
            enterCommand();
        }

        if(strcmp(command, "printBeginning")==0){
            int temp;
            printf("How much packets do you want to print\n");
            scanf("%d", &temp);
            if(temp > packetNum){
                printf("Returning to default, entered number is bigger than number of packets\n");
                enterCommand();
            }
            else{
            char tempState[3];
            printf("Do you want to print Hexdump?(enter yes or no)\n");
            scanf("%s", tempState);
            if(strcmp(tempState, "yes")==0){
                printf("Printing packets\n");
                printPackets(1, 0, packetNum-temp);
            }
            if(strcmp(tempState, "no")==0){
                printf("Printing packets\n");
                printPackets(0, 0, packetNum-temp);
            }
            if(strcmp(tempState, "yes")!=0 && strcmp(tempState, "no")!=0){
                printf("Returning to default, please enter correct data\n");
            }
                enterCommand();
            }
        }

    if(strcmp(command, "printEnd")==0) {
        int temp;
        printf("How much packets do you want to print\n");
        scanf("%d", &temp);
        if(temp > packetNum){
            printf("Returning to default, entered number is bigger than number of packets\n");
            enterCommand();
        }
        else{
            char tempStatement[3];
            printf("Do you want to print Hexdump?(enter yes or no)\n");
            scanf("%s", tempStatement);
            if (strcmp(tempStatement, "yes") == 0) {
                printf("Printing packets\n");
                printPackets(1, packetNum-temp, packetNum);
            }
            if (strcmp(tempStatement, "no") == 0) {
                printf("Printing packets\n");
                printPackets(0, packetNum-temp, packetNum);
            }
            if (strcmp(tempStatement, "yes") != 0 && strcmp(tempStatement, "no") != 0) {
                printf("Returning to default, please enter correct data\n");
            }
            enterCommand();
        }

    }

        if(strcmp(command, "exit")==0){
            exit(0);
        }

        if(strcmp(command, "help")!=0 && strcmp(command, "start")!=0
           && strcmp(command, "print")!=0 && strcmp(command, "deleteData")!=0
           && strcmp(command, "exit")!=0 && strcmp(command, "")!=0
           && strcmp(command, "printBeginning")!=0 && strcmp(command, "printEnd")!=0){
        printf("Please enter the correct command\n");
            enterCommand();
        }

}


void printPackets(int hexPrint, int beginning, int end){
    int tcp =0;
    int udp =0;
    int icmp =0;
    int igmp =0;
    for(int ip=beginning;ip<end;ip++) {
        printf("\n ------The packet number %d ------\n\n", ip);
        printf("IP Header: \n");
        printf("IP version - %u\n", ipHeadr[ip].ipVer);
        printf("IP header length in DWORDS - %u\n", ipHeadr[ip].headerDWORDS);
        printf("IP header length in bytes - %u\n", ipHeadr[ip].headerBytes);
        printf("Type of service - %u\n", ipHeadr[ip].typeOfService);
        printf("IP total length - %u\n", ipHeadr[ip].ipLength);
        printf("Identification - %u\n", ipHeadr[ip].ident);
        printf("TTL - %u\n", ipHeadr[ip].ttl);
        printf("Protocol - %u\n", ipHeadr[ip].protocolNum);
        printf("Checksum - %u\n", ipHeadr[ip].checkSum);
        printf("Source IP - %s\n", addrHeadr[ip].srcIP);
        printf("Destination IP - %s\n", addrHeadr[ip].destIP);
        if (ipHeadr[ip].protocol == 6){
            printf("TCP Header: \n\n");
            printf("Source port - %u\n", tcpHeadr[tcp].srcPort);
            printf("Destination port - %u\n", tcpHeadr[tcp].destPort);
            printf("Sequence number - %u\n", tcpHeadr[tcp].sequenceNum);
            printf("Acknowledgement number - %u\n", tcpHeadr[tcp].acknoledgeNum);
            printf("TCP header length in DWORDS - %u\n", tcpHeadr[tcp].headerLengthDWORDS);
            printf("TCP header length in bytes - %u\n", tcpHeadr[tcp].headerLengthBytes);
            printf("Urgent flag - %u\n", tcpHeadr[tcp].urgentFlag);
            printf("Acknowledgement flag - %u\n", tcpHeadr[tcp].acknoledgeFlag);
            printf("Push flag - %u\n", tcpHeadr[tcp].pushFlag);
            printf("Reset flag - %u\n", tcpHeadr[tcp].resetFlag);
            printf("Synchronization flag - %u\n", tcpHeadr[tcp].syncFlag);
            printf("Finish flag - %u\n", tcpHeadr[tcp].finishFlag);
            printf("Window - %d\n", tcpHeadr[tcp].windowNum);
            printf("Checksum - %d\n", tcpHeadr[tcp].checkSum);
            printf("Urgent pointer - %d\n", tcpHeadr[tcp].urgentPointer);
            tcp++;
        }
        if (ipHeadr[ip].protocol==17){
            printf("UDP Header: \n\n");
            printf("Source port - %u\n", udpHeadr[udp].srcPort);
            printf("Destiantion port - %u\n", udpHeadr[udp].destPort);
            printf("UDP length - %u\n", udpHeadr[udp].length);
            printf("Checksum - %u\n", udpHeadr[udp].checkSum);
            udp++;
        }
        if(ipHeadr[ip].protocol==1){
            printf("ICMP Header: \n\n");
            printf("ICMP type - %u\n", icmpHeadr[icmp].type);
            printf("ICMP code - %u\n", icmpHeadr[icmp].code);
            printf("ICMP message - %s\n", icmpHeadr[icmp].msg);
            printf("Checksum - %u\n", icmpHeadr[icmp].checkSum);
            icmp++;
        }
        if(ipHeadr[ip].protocol==2){
            printf("IGMP Header: \n\n");
            printf("IGMP type - %u\n", igmpHeadr[igmp].type);
            printf("IGMP code - %u\n", igmpHeadr[igmp].code);
            printf("Checksum - %u\n", igmpHeadr[igmp].checkSum);
            printf("IGMP group - %u\n", igmpHeadr[igmp].group);
            igmp++;
        }
        if (hexPrint==1){
            printf("Hexdump: \n\n");
            for(int i=0 ; i < hexHeadr[ip].size ; i++) // beggining
            {
                if( i!=0 && i%16==0)   //after hex line
                {
                    printf("         "); //space after hex line
                    for(int j=i-16 ; j<i ; j++)
                    {
                        if(hexHeadr[ip].hexBuff[j]>=32 && hexHeadr[ip].hexBuff[j]<=128) {
                            printf("%c",hexHeadr[ip].hexBuff[j]); //printing this data
                        }
                        else {
                            printf(".");
                        } //otherwise print a dot
                    }
                    printf("\n");
                }

                if(i%16==0)
                    printf("   ");
                printf(" %02X",(unsigned int)hexHeadr[ip].hexBuff[i]);

                if( i==hexHeadr[ip].size-1)  //print the last spaces
                {
                    for(int j=0;j<15-i%16;j++)
                        printf("   "); //extra spaces

                    printf("         ");

                    for(int j=i-i%16 ; j<=i ; j++)
                    {
                        if(hexHeadr[ip].hexBuff[j]>=32 && hexHeadr[ip].hexBuff[j]<=128){
                            printf("%c",hexHeadr[ip].hexBuff[j]);
                        }
                        else {
                            printf(".");
                        }
                    }
                    printf("\n");
                }
            }

        }
}}

int kbhit (void)
{
    struct timeval tv;
    fd_set rdfs;

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    FD_ZERO(&rdfs);
    FD_SET (STDIN_FILENO, &rdfs);

    select(STDIN_FILENO+1, &rdfs, NULL, NULL, &tv);
    return FD_ISSET(STDIN_FILENO, &rdfs);

}

void gettingPacket(unsigned char * buff, int data){
    //reallocating memory for new packets
    packetNum++;
    ipHeadr = realloc(ipHeadr, sizeof(*ipHeadr)*packetNum);
    addrHeadr = realloc(addrHeadr,sizeof(*addrHeadr)*packetNum);
    hexHeadr = realloc(hexHeadr, sizeof(*hexHeadr)*packetNum);
    //existing data struct reference, line 27
    struct iphdr *iph = (struct iphdr*)buff;


    switch (iph -> protocol)
    {
        //protocol, that icmp using is 1
        case 1:
            icmpNum++;
            icmpHeadr = realloc(icmpHeadr, sizeof(*icmpHeadr)*icmpNum);
            icmpOutput(buff, data);
            break;
        //protocol, that igmp using is 2
        case 2:
            igmpNum++;
            igmpHeadr = realloc(igmpHeadr,sizeof(*igmpHeadr)*igmpNum);
            igmpOutput(buff, data);
            break;
        //protocol, that tcp using is 6
        case 6:
            tcpNum++;
            tcpHeadr = realloc(tcpHeadr,sizeof(*tcpHeadr)*tcpNum);
            tcpPacketOutput(buff, data);
            break;
            //protocol, that udp using is 17
        case 17:
            udpNum++;
            udpHeadr = realloc(udpHeadr, sizeof(*udpHeadr)*udpNum);
            udpPacketOutput(buff, data);
            break;

    }
}

void tcpPacketOutput(unsigned char * buff, int data){

    unsigned short ipHeaderLength;
    //existing data struct reference, line 27
    struct iphdr *iph = (struct iphdr*)buff;
    ipHeaderLength = iph->ihl*4;

    //existing data struct reference, line 28
    struct tcphdr *tcph = (struct tcphdr*)(buff + ipHeaderLength);

    ipHeaderOutput(buff, data);
    //copying data from packet to struct
    tcpHeadr[tcpNum-1].srcPort = ntohs (tcph->source);
    tcpHeadr[tcpNum-1].destPort = ntohs (tcph->dest);
    tcpHeadr[tcpNum-1].sequenceNum = ntohl(tcph->seq);
    tcpHeadr[tcpNum-1].acknoledgeNum = ntohl(tcph->ack_seq);
    tcpHeadr[tcpNum-1].headerLengthDWORDS = (unsigned int)tcph->doff;
    tcpHeadr[tcpNum-1].headerLengthBytes = (unsigned int)tcph->doff*4;
    tcpHeadr[tcpNum-1].urgentFlag = (unsigned int)tcph->urg;
    tcpHeadr[tcpNum-1].acknoledgeFlag = (unsigned int)tcph->ack;
    tcpHeadr[tcpNum-1].pushFlag = (unsigned int)tcph->psh;
    tcpHeadr[tcpNum-1].resetFlag = (unsigned int)tcph->rst;
    tcpHeadr[tcpNum-1].syncFlag = (unsigned int)tcph->syn;
    tcpHeadr[tcpNum-1].finishFlag = (unsigned int)tcph->fin;
    tcpHeadr[tcpNum-1].windowNum = ntohs(tcph->window);
    tcpHeadr[tcpNum-1].checkSum = ntohs(tcph->check);
    tcpHeadr[tcpNum-1].urgentPointer = tcph->urg_ptr;
    hexDataOut(buff + ipHeaderLength + sizeof tcph , (data - sizeof tcph - iph->ihl * 4));
}

void udpPacketOutput(unsigned char * buff, int data){

    unsigned short ipHeaderLength;
    //existing data struct reference, line 27
    struct iphdr *iph = (struct iphdr*)buff;
    ipHeaderLength = iph->ihl*4;
    //existing data struct reference, line 29
    struct udphdr *udph = (struct udphdr*)(buff + ipHeaderLength);
    ipHeaderOutput(buff, data);
    //copying data from packet to struct
    udpHeadr[udpNum-1].srcPort = ntohs(udph->source);
    udpHeadr[udpNum-1].destPort = ntohs(udph->dest);
    udpHeadr[udpNum-1].length = ntohs(udph->len);
    udpHeadr[udpNum-1].checkSum = ntohs(udph->check);
    hexDataOut(buff + ipHeaderLength + sizeof udph , (data - sizeof udph - iph->ihl * 4));
}

int ipHeaderOutput(unsigned char * buff, int data){
    //existing data struct reference, line 27
    struct iphdr *iph = (struct iphdr*)buff;
    //fill the struct with 0
    memset(&src, 0, sizeof(src));
    memset(&dest, 0, sizeof(dest));
    //source ip address
    src.sin_addr.s_addr = iph->saddr;
    //destination ip address
    dest.sin_addr.s_addr = iph->daddr;
    //copying data from packet to struct
    ipHeadr[packetNum-1].ipVer = iph->version;
    ipHeadr[packetNum-1].headerDWORDS = (unsigned int)iph->ihl;
    ipHeadr[packetNum-1].headerBytes = (unsigned int)iph->ihl*4;
    ipHeadr[packetNum-1].typeOfService = (unsigned int)iph->tos;
    ipHeadr[packetNum-1].ipLength = ntohs(iph->tot_len);
    ipHeadr[packetNum-1].ident =  ntohs(iph->id);
    ipHeadr[packetNum-1].ttl = (unsigned int)iph->ttl;
    ipHeadr[packetNum-1].protocolNum = (unsigned int)iph->protocol;
    ipHeadr[packetNum-1].checkSum = ntohs(iph->check);
    ipHeadr[packetNum-1].protocol =iph -> protocol;

    strcpy(addrHeadr[packetNum-1].srcIP, inet_ntoa(src.sin_addr));
    strcpy(addrHeadr[packetNum-1].destIP, inet_ntoa(dest.sin_addr));

}

void icmpOutput(unsigned char * buff, int data){

    unsigned short ipHeaderLength;
    //existing data struct reference, line 27
    struct iphdr *iph = (struct iphdr*)buff;
    ipHeaderLength = iph->ihl*4;
    //existing data struct reference, line 30
    struct icmphdr *icmph = (struct icmphdr*)(buff + ipHeaderLength);
    ipHeaderOutput(buff, data);
    /*type, code, checksum*/
    //copying data from packet to struct
    icmpHeadr[icmpNum-1].type = (unsigned int)icmph->type;
    icmpHeadr[icmpNum-1].code = (unsigned int)icmph->code;
    icmpHeadr[icmpNum-1].checkSum = ntohs(icmph->checksum);
    switch (icmph -> type){
        // type 0 - echo reply (ping)
        case 0:
            strcpy(icmpHeadr[icmpNum-1].msg, "Echo (ping) reply");
            break;
        //type 3 - destination is unreachable
        case 3:
            if ((unsigned int)icmph->code>=0 && (unsigned int)icmph->code<=4 ){
                strcpy(icmpHeadr[icmpNum-1].msg, "Destination network/port/protocol/host unreachable");
            }
            else if ((unsigned int)icmph->code == 4){
                strcpy(icmpHeadr[icmpNum-1].msg, "Fragmentation required, and DF flag set");
            }
            else if ((unsigned int)icmph->code == 4){
                strcpy(icmpHeadr[icmpNum-1].msg, "Fragmentation required, and DF flag set");
            }
            else if ((unsigned int)icmph->code == 5 || (unsigned int)icmph->code == 8){
                strcpy(icmpHeadr[icmpNum-1].msg, "Source route failed/host isolated");
            }
            else if ((unsigned int)icmph->code == 6 || (unsigned int)icmph->code == 7){
                strcpy(icmpHeadr[icmpNum-1].msg, "Destination network/host unknown");
            }
            else if ((unsigned int)icmph->code == 9 || (unsigned int)icmph->code == 10){
                strcpy(icmpHeadr[icmpNum-1].msg, "Network/host administratively prohibited");
            }
            else if ((unsigned int)icmph->code == 11 || (unsigned int)icmph->code == 12){
                strcpy(icmpHeadr[icmpNum-1].msg, "Network/host unreachable for ToS");
            }
            if ((unsigned int)icmph->code>=12 && (unsigned int)icmph->code<=15){
                strcpy(icmpHeadr[icmpNum-1].msg, "Communication administratively prohibited");
            }
        //type 5 - redirect package
        case 5:
            switch (icmph->code){
                case 1:
                    strcpy(icmpHeadr[icmpNum-1].msg, "Redirect Datagram for the Network");
                    break;
                case 2:
                    strcpy(icmpHeadr[icmpNum-1].msg, "Redirect Datagram for the Host");
                    break;
                case 3:
                    strcpy(icmpHeadr[icmpNum-1].msg, "Redirect Datagram for the ToS & network");
                    break;
                case 4:
                    strcpy(icmpHeadr[icmpNum-1].msg, "Redirect Datagram for the ToS & host");
                    break;
            }
            break;
        //type 8 - echo request (ping)
        case 8:
            strcpy(icmpHeadr[icmpNum-1].msg, "Echo (ping) request");
            break;
        //type 11 - time exeeded (dead package)
        case 11:
            switch (icmph->code) {
                case 1:
                    strcpy(icmpHeadr[icmpNum-1].msg, "TTL expired in transit");
                    break;
                case 2:
                    strcpy(icmpHeadr[icmpNum-1].msg, "\tFragment reassembly time exceeded");
                    break;
            }
            break;
        //type 12 - missing parameter/ip header problem
        case 12:
            switch (icmph->code){
        case 1:
            strcpy(icmpHeadr[icmpNum-1].msg, "Pointer indicates the error");
            break;
        case 2:
            strcpy(icmpHeadr[icmpNum-1].msg, "Missing a required option");
            break;
        case 3:
            strcpy(icmpHeadr[icmpNum-1].msg, "Bad length");
            break;
            }
        //type 40 - security fail
        case 40:
            switch (icmph->code){
                case 1:
                    strcpy(icmpHeadr[icmpNum-1].msg, "Unknown security option index");
                    break;
                case 2:
                    strcpy(icmpHeadr[icmpNum-1].msg, "Authentication error (security options are ok)");
                    break;
                case 3:
                    strcpy(icmpHeadr[icmpNum-1].msg, "Decrypting error (security options are ok)");
                    break;
                case 4:
                    strcpy(icmpHeadr[icmpNum-1].msg, "Need Authentication");
                    break;
                case 5:
                    strcpy(icmpHeadr[icmpNum-1].msg, "Need Authorization");
                    break;
            }
            break;
    }
    hexDataOut(buff + ipHeaderLength + sizeof icmph , (data - sizeof icmph - iph->ihl * 4));
}

void igmpOutput(unsigned char * buff, int data){

    unsigned short ipHeaderLength;
    //existing data struct reference, line 27
    struct iphdr *iph = (struct iphdr*)buff;
    ipHeaderLength = iph->ihl*4;
    //existing data struct reference, line 31
    struct igmphdr *igmph = (struct igmphdr*)(buff + ipHeaderLength);
    ipHeaderOutput(buff, data);

    //copying data from packet to struct
    igmpHeadr[igmpNum-1].type = igmph->type;
    igmpHeadr[igmpNum-1].code = igmph->code;
    igmpHeadr[igmpNum-1].checkSum = ntohs(igmph->csum);
    igmpHeadr[igmpNum-1].group = ntohs(igmph->group);
    hexDataOut(buff + ipHeaderLength + sizeof igmph , (data - sizeof igmph - iph->ihl * 4));
}

void hexDataOut(unsigned char * buff, int data){
    //copying data from packet to struct
    hexHeadr[packetNum-1].size = data;
    hexHeadr[packetNum-1].hexBuff = malloc(sizeof(*buff));
    strcpy(hexHeadr[packetNum-1].hexBuff, buff);
    //fprintf(logfile,"%c",(unsigned char)data[j]);
    //fprintf(logfile," %02X",(unsigned int)data[i]);
}
