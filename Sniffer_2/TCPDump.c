/**
 *Progra que simula un sniffer para capturar datos de tipo tcp, udp, icmp, igmp y otros
 *Sergio Amaro Rosas
 */

#include<stdio.h>
#include<stdlib.h>    //malloc                                                                                                                        
#include<string.h>    //memset                                                                                                                        
#include<netinet/ip_icmp.h>   //Provee las declaraciones para las cabeceras de icmp                                                                   
#include<netinet/udp.h>   //Provee las declaraciones para las cabeceras de udp                                                                        
#include<netinet/tcp.h>   //Provee las declaraciones para las cabeceras de tcp                                                                        
#include<netinet/ip.h>    //Provee las declaraciones para las cabeceras de ip                                                                         
#include<netinet/igmp.h>
#include<sys/socket.h>
#include<arpa/inet.h>

void procesaPaquete(unsigned char* , int);
void imprimeCabeceraIP(unsigned char* , int);
void imprimePaqueteTCP(unsigned char* , int);
void imprimePaqueteUDP(unsigned char * , int);
void imprimePaqueteICMP(unsigned char* , int);
void imprimePaqueteIGMP(unsigned char*, int);
void imprimeDatos (unsigned char* , int);


int sraw;
struct sockaddr_in source,dest;
FILE *logfile;
int udp = 0;
int tcp = 0;
int icmp =0;
int igmp = 0;
int otros = 0;
int total = 0;
int tiempo = 0;
int i,j;
struct sockaddr_in origen,destino;

/**
 *Funcion que procesa los paquetes y dependiendo del paquete es como los va a imprimir y a contar
 */
void procesaPaquete(unsigned char* buffer, int tam){
  struct iphdr *iph = (struct iphdr*)buffer;
  
  switch(iph->protocol){
  case 1:
    ++icmp;
    ++total;
    imprimePaqueteICMP(buffer, tam);
    break;
  case 2:
    ++igmp;
    ++total;
    imprimePaqueteIGMP(buffer, tam);
    break;
  case 6:
    ++tcp;
    ++total;
    imprimePaqueteTCP(buffer,tam);
  case 17:
    ++udp;
    ++total;
    imprimePaqueteUDP(buffer,tam);
  default:
    ++otros;
    ++total;
  }
 
}

/**
 *Función que imprime la cabecera IP
 *
 */
void imprimeCabeceraIP(unsigned char* buffer, int tam){
  unsigned short iplen;
  struct iphdr *iph = (struct iphdr*)buffer;
  iplen = iph->ihl*4;
  memset(&origen, 0, sizeof(origen));
  memset(&destino,0,sizeof(destino));
  origen.sin_addr.s_addr = iph->saddr;
  destino.sin_addr.s_addr = iph->daddr;
  
  fprintf(logfile,"\nCabezera IP\n\n");
  fprintf(logfile,"Version                : %s\n",iph -> version == 4 ? "IPv4" : "IPv6");
  fprintf(logfile,"Tamaño de la cabecera  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
  fprintf(logfile,"Tipo de servicio       : %d\n",(unsigned int)iph->tos);
  fprintf(logfile,"Tamaño total de IP     : %d Bytes\n",ntohs(iph->tot_len));
  fprintf(logfile,"TTL                    : %d\n",(unsigned int)iph->ttl);
  fprintf(logfile,"Protocolo              : %d\n",(unsigned int)iph->protocol);
  fprintf(logfile,"Checksum               : %d\n",ntohs(iph->check));
  fprintf(logfile,"IP Origen              : %s\n",inet_ntoa(source.sin_addr));
  fprintf(logfile,"IP Destino             : %s\n",inet_ntoa(dest.sin_addr));
}

/**
 *FUncion que imprime los paquetes de la forma ICMP
 */
void imprimePaqueteICMP(unsigned char* buffer, int tam){
  unsigned short iplen;
  struct iphdr *iph = (struct iphdr*)buffer;
  iplen = iph->ihl*4;
  struct icmphdr *icmph = (struct icmphdr*)(buffer + iplen);
  fprintf(logfile,"\n\n*******************Paquete ICMP*****************\n");
  imprimeCabeceraIP(buffer,tam);
  fprintf(logfile,"\nCabezera ICMP\n");
  fprintf(logfile,"Tipo                   : %d",(unsigned int)(icmph->type));
  if((unsigned int)(icmph->type) == 11){
    fprintf(logfile,"  (Tiempo de Vida expirado)\n");
  }else{
    if((unsigned int)(icmph->type) == ICMP_ECHOREPLY){
      fprintf(logfile,"  (ICMP Echo Reply)\n");
    }
  }
  fprintf(logfile,"Codigo                 : %d\n",(unsigned int)(icmph->code));
  fprintf(logfile,"Checksum               : %d\n",ntohs(icmph->checksum));
  fprintf(logfile,"\n                  Data Dump               \n");
  fprintf(logfile,"Cabecera IP\n");
  imprimeDatos(buffer,iplen);
  fprintf(logfile,"Cabecera ICMP\n");
  imprimeDatos(buffer+iplen,sizeof icmph);
  fprintf(logfile,"Data Payload\n");
  imprimeDatos(buffer+iplen+sizeof icmph,(tam - sizeof icmph-iph->ihl*4));
  fprintf(logfile,"\n#####################################################\n");
}

/**
 *Funcion que imprime los paquetes de la forma IGMP
 */
void imprimePaqueteIGMP(unsigned char* buffer, int tam){
  unsigned short iplen;
  struct iphdr *iph = (struct iphdr*)buffer;
  iplen = iph->ihl*4;
  struct igmp *igmph = (struct igmp*)(buffer + iplen);
  
  fprintf(logfile,"\n\n*******************Paquete IGMP*****************\n");
  imprimeCabeceraIP(buffer,tam);
  fprintf(logfile,"\nCabezera IGMP\n");
  fprintf(logfile,"Tipo                   : %u\n",ntohs(igmph->igmp_type));
  fprintf(logfile,"Codigo de Ruteo        : %u\n",ntohs(igmph->igmp_code));
  fprintf(logfile,"Checksum               : %d\n\n",ntohs(igmph->igmp_cksum));
  fprintf(logfile,"\n                  Data Dump               \n");
  fprintf(logfile,"Cabecera IP\n");
  imprimeDatos(buffer,iplen);
  fprintf(logfile,"Cabecera IGMP\n");
  imprimeDatos(buffer+iplen,sizeof igmph);
  fprintf(logfile,"Data Payload\n");
  imprimeDatos(buffer+iplen+sizeof igmph,(tam - sizeof igmph-iph->ihl*4));
  fprintf(logfile,"\n#####################################################\n");
}

/**
 *FUncion que imprime los paquetes de la forma TCP
 */
void imprimePaqueteTCP(unsigned char* buffer, int tam){
  unsigned short iplen;
  struct iphdr *iph = (struct iphdr*)buffer;
  iplen = iph->ihl*4;
  struct tcphdr *tcph = (struct tcphdr*)(buffer + iplen);
  fprintf(logfile,"\n\n*******************Paquete TCP*****************\n");
  imprimeCabeceraIP(buffer,tam);
  fprintf(logfile,"\nCabezera TCP\n");
  fprintf(logfile,"Puerto Origen          : %u\n",ntohs(tcph->source));
  fprintf(logfile,"Puerto Destino         : %u\n",ntohs(tcph->dest));
  fprintf(logfile,"Numero de secuencias   : %u\n",ntohl(tcph->seq));
  fprintf(logfile,"Numero de Ack          : %u\n",ntohl(tcph->ack_seq));
  fprintf(logfile,"Tamaño de la cabecera  : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
  fprintf(logfile,"Urgent Flag            : %d\n",(unsigned int)tcph->urg);
  fprintf(logfile,"Acknowledgement Flag   : %d\n",(unsigned int)tcph->ack);
  fprintf(logfile,"Synchronise Flag       : %d\n",(unsigned int)tcph->syn);
  fprintf(logfile,"Finish Flag            : %d\n",(unsigned int)tcph->fin);
  fprintf(logfile,"Ventana                : %d\n",ntohs(tcph->window));
  fprintf(logfile,"Checksum               : %d\n",ntohs(tcph->check));
  fprintf(logfile,"\n                  Data Dump               \n");
  fprintf(logfile,"Cabecera IP\n");
  imprimeDatos(buffer,iplen);
  fprintf(logfile,"Cabecera TCP\n");
  imprimeDatos(buffer+iplen,tcph->doff*4);
  fprintf(logfile,"Data Payload\n");
  imprimeDatos(buffer + iplen + tcph->doff*4 , (tam - tcph->doff*4-iph->ihl*4) );
  fprintf(logfile,"\n#####################################################\n");
}

/**
 *Funcion que imrpime los datos de la forma UDP
 */
void imprimePaqueteUDP(unsigned char* buffer, int tam){
  unsigned short iplen;
  struct iphdr *iph = (struct iphdr*)buffer;
  iplen = iph->ihl*4;
  struct udphdr *udph = (struct udphdr*)(buffer + iplen);
  fprintf(logfile,"\n\n*******************Paquete UDP*****************\n");
  imprimeCabeceraIP(buffer,tam);
  fprintf(logfile,"\nCabezera UDP\n");
  fprintf(logfile,"Puerto Origen          : %d\n" , ntohs(udph->source));
  fprintf(logfile,"Puerto Destino         : %d\n" , ntohs(udph->dest));
  fprintf(logfile,"Tamaño de la cabecera  : %d\n" , ntohs(udph->len));
  fprintf(logfile,"Checksum               : %d\n" , ntohs(udph->check));
  fprintf(logfile,"\n                  Data Dump               \n");
  fprintf(logfile,"IP Header\n");
  imprimeDatos(buffer , iplen);
  fprintf(logfile,"UDP Header\n");
  imprimeDatos(buffer+iplen , sizeof udph);
  fprintf(logfile,"Data Payload\n");
  imprimeDatos(buffer + iplen + sizeof udph ,( tam - sizeof udph - iph->ihl * 4 ));  
  fprintf(logfile,"\n#####################################################\n");
}

/**
 *Funcion que imprime los datos que contiene cada paquete en forma hexadecimal y otros
 */
void imprimeDatos(unsigned char* buffer, int tam){
  for(i=0 ; i < tam ; i++){
    if( i!=0 && i%16==0){    
      fprintf(logfile,"         ");
      for(j=i-16 ; j<i ; j++){
	if(buffer[j]>=32 && buffer[j]<=128){
	  fprintf(logfile,"%c",(unsigned char)buffer[j]);                                                       
	}else fprintf(logfile,".");                                                                                    
      }
      fprintf(logfile,"\n");
    }
    if(i%16==0) fprintf(logfile,"   ");
    fprintf(logfile," %02X",(unsigned int)buffer[i]);
    if( i==tam-1){                                                                                                         
      for(j=0;j<15-i%16;j++){
	fprintf(logfile,"   ");
      }
      fprintf(logfile,"         ");
      for(j=i-i%16 ; j<=i ; j++){
	if(buffer[j]>=32 && buffer[j]<=128) fprintf(logfile,"%c",(unsigned char)buffer[j]);
	else fprintf(logfile,".");
      }
      fprintf(logfile,"\n");
    }
  }
}

/**
 *FUncion Main
 */
int main(int argc, char* argv[]){
  int saddr_size, data_size;
  struct sockaddr saddr;
  struct in_addr in;
  unsigned char *buffer = (unsigned char *)malloc(65536);
  int contador = 0;
  if(argc < 3){
    printf("\nLos parametros son incorrectos\n");
    printf("Se deben de proporcionar de la siguiente manera sudo ./TCPDump interfaz NumeroDeDuracionDelPrograma\n\n Ejemplo: sudo ./TCPDump wlan0 20\n");
    return 1;
  }
  
  if(atoi(argv[2]) < 0){
    printf("\nEl numero de duración del programa tiene que ser entero y no negativo\n");
    return 1;
  }
  
  logfile=fopen("Capturas.txt","w");
  
  if(logfile == NULL){
    printf("\nNo se pudo crear el archivo\n");
  }
  sraw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if(sraw < 0){
    printf("\nError al crear el socket, será por las bibliotecas o te falto ejecutarlo como super usuario\n");
    return 1;
  }
  printf("\nEmpezando a capturar paquetes............\n");
  while(contador != atoi(argv[2])){
    saddr_size = sizeof saddr;
    data_size = recvfrom(sraw, buffer, 65536, 0, &saddr, &saddr_size);
    if(data_size < 0){
      printf("\nError al recuperar paquetes\n");
      return 1;
    }
    
    procesaPaquete(buffer, data_size);
    contador++;
  }
   printf("\n**********Numero de Paquetes capturados*********\n");
   printf("\nICMP: %d  - IGMP: %d  - TCP: %d  - UDP: %d  - Otros: %d\n", icmp,igmp,tcp,udp,otros);
   printf("Total de Paquetes Capturados: %d\n\n", total);
   close(sraw);
   printf("\nEl respaldo de la captura se guarda en un archivo creado llamado Capturas.txt\n");
   printf("\n******************Fin del Sniffer by Cheko*****************\n\n");
   return 0;
}
