/**
 *Aplicacion que hace capturas de paquetes 
 *Ya sea TCP,UDP,ICMP, IGMP y otros
 *
 */

#include<stdio.h> //Para cosas estandar
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<netinet/ip_icmp.h>   //Provee las declaraciones para las cabeceras de icmp
#include<netinet/udp.h>   //Provee las declaraciones para las cabeceras de udp
#include<netinet/tcp.h>   //Provee las declaraciones para las cabeceras de tcp
#include<netinet/ip.h>    //Provee las declaraciones para las cabeceras de ip
#include<netinet/igmp.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <sys/ioctl.h> 
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
 
void procesaPaquete(unsigned char*, int);
void imprimeCabeceraIP(unsigned char*, int);
void imprimePaqueteTCP(unsigned char*, int);
void imprimePaqueteUDP(unsigned char *, int);
void imprimePaqueteICMP(unsigned char*, int);
void imprimeDatos (unsigned char*, int);
 
int sock_raw;
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
//struct sockaddr_in source,dest;
struct sockaddr_ll soll;
struct ifreq ifr;
struct ethhdr *eth_cabezera;
struct iphdr *ip_cabezera;

void imprimeCabeceraIP(unsigned char* paquete, int len){
  struct ethhdr *et;
  struct iphdr *cabezera;
  et = (struct ethhdr *)paquete;
  if(ntohs(et -> h_proto) == ETH_P_IP){
    if(len >= ((sizeof(struct ethhdr) + (sizeof(struct iphdr))))){
      cabezera = (struct iphdr*)(paquete + sizeof (struct ethhdr));
      printf("IP Header\n");
      printf("Version                  : %s\n",cabezera -> version == 4 ? "IPv4" : "IPv6");
      printf("Tamaño de la cabecera    : %d(bytes)\n",cabezera -> ihl*4);
      printf("Tipo de servicio         : %d\n", cabezera -> tos);
      printf("Tamaño total de la info  : %d\n", cabezera -> tot_len);
      printf("TTL                      : %d\n",cabezera -> ttl);
      printf("Protocol                 : %d\n", cabezera -> protocol);
      printf("Checksum                 : %d\n",cabezera -> check);
      printf("IP Origen                : %d\n",cabezera -> saddr);
      printf("IP Destino               : %d\n",cabezera -> daddr);
      
    }else{
      printf("La cabezera IP esta incompleta");
    }
  }  
}

void imprimePaqueteTCP(unsigned char* paquete, int len){
  struct ethhdr *et;
  struct iphdr *iph;
  struct tcphdr *cabecera_tcp;
  
  if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))){
    et = (struct ethhdr *)paquete;
    if(ntohs(et -> h_proto) == ETH_P_IP){
      iph = (struct iphdr *)(paquete + sizeof(struct ethhdr));
      if(iph -> protocol == IPPROTO_TCP){
	printf("\nTCP Header\n");
	printf("Puerto de Origen       : %d\n",cabecera_tcp -> source);
	printf("Puerto de Destino      : %d\n",cabecera_tcp -> dest);
	printf("Numero de secuencia    : %d\n",cabecera_tcp -> seq);
	printf("Numero de ack          : %d\n",cabecera_tcp -> ack_seq);
	printf("Tamaño de la cabecera  : %d\n",cabecera_tcp -> doff*4);
	printf("Urgent Flag            : %d\n",cabecera_tcp -> urg);
	printf("Acknowledgement Flag   : %d\n", cabecera_tcp -> ack);
	printf("Synchronise Flag       : %d\n", cabecera_tcp -> syn);
	printf("Finish Flag            : %d\n",cabecera_tcp -> fin);
	printf("Ventana                : %d\n",cabecera_tcp -> window);
	printf("Checksum               : %d\n",cabecera_tcp -> check);
	
      }
    }
  }
}

void procesaPaquete(unsigned char* paquete, int len){
  eth_cabezera = (struct ethhdr *)paquete;
  
  if(ntohs(eth_cabezera -> h_proto) == ETH_P_IP){
    ip_cabezera = (struct iphdr *)(paquete + sizeof(struct ethhdr));
    if((ip_cabezera -> protocol) == IPPROTO_TCP){
      printf("\n***********Paquete TCP**********\n");
      imprimeCabeceraIP(paquete,len);
      imprimePaqueteTCP(paquete, len);
    }
  }
}


int main(int argc, char* argv[]){
 
  int paquete_size = sizeof(soll);
  int data_size;
  unsigned char *buffer = (unsigned char *)malloc(65536); // D: D: 
  
  if(argc < 2){
    printf("Error: Los parametros son incorrectos\n");
    printf("Se deben de proporcionar de la siguiente manera\n sudo ./TCPDump interfaz");
  }

  
  logfile=fopen("log.txt","w");
  if(logfile==NULL) printf("No es posible crear el archivo.");
  printf("Iniciando...\n");
  //Creamos un socket raw donde vamos a estar realizando el sniffing.
  sock_raw = socket(PF_INET,SOCK_RAW,ETH_P_IP);
  if(sock_raw < 0){
    printf("Error en el socket or Necesitas estar como superusuario\n");
    return 1;
  }
 
  printf("\nCreado el socket_raw\n");

  bzero(&soll,sizeof(soll));
  bzero(&ifr,sizeof(ifr));

  strncpy((char *)ifr.ifr_name,argv[1], IFNAMSIZ);
  if((ioctl(sock_raw,SIOCGIFINDEX,&ifr)) == -1){
    printf("Error Recuperando interfaz de escucha");
    exit(1);
  }

  soll.sll_family = AF_PACKET;
  soll.sll_ifindex = ifr.ifr_ifindex;
  soll.sll_protocol = htons(ETH_P_IP);
  
  if(bind(sock_raw,(struct sockaddr *) &soll,sizeof(struct sockaddr_ll)) == -1){
    printf("Error al hacer el bind\n");
    exit(1);
  }  
  /**
  int yes=1; 
  

  // lose the pesky "Address already in use" error message 
  if (setsockopt(sock_raw,SOL_SOCKET,SO_REUSEADDR,&soll,sizeof(soll)) == -1) { 
    perror("setsockopt"); 
    exit(1); 
  }  
  */

  while(1){
    //Recibe los paquetes
    data_size = recvfrom(sock_raw , buffer , 65536 , 0 ,(struct sockaddr*) &soll , &paquete_size);
    if(data_size <0 ){
      printf("Error recuperando los paquetes\n");
      return 1;
    }
    //En esta función procesamos el paquete.
    printf("Entrooooooo");
    procesaPaquete(buffer , data_size);
  }
  close(sock_raw);
  printf("Terminado");
  return 0;
}

