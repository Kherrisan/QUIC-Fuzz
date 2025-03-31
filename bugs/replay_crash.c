// author: Kian Kai Ang
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <poll.h>

/* Expected arguments:
1. crash_input file
2. Server's network port
*/

int main(int argc, char* argv[])
{
  FILE *fp;
  int portno, n;
  struct sockaddr_in serv_addr;
  char* buf = NULL;
  char temp_buf[5000];
  unsigned int size, packet_count = 0;

  fp = fopen(argv[1],"rb");
  portno = atoi(argv[2]);

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sockfd < 0) {
    fprintf(stderr,"Cannot create a UDP socket.\n");
  }

  memset(&serv_addr, '0', sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  //Send packet one by one
  while(!feof(fp)) {
    if (buf) {free(buf); buf = NULL;}
    // get the size of the current packet
    if (fread(&size, sizeof(unsigned int), 1, fp) > 0) {
      packet_count++;
    	fprintf(stderr,"\nSending packet %d with %d bytes\n", packet_count, size);

      // get the current packet
      buf = (char *)malloc(size);
      fread(buf, size, 1, fp);

      // send packet
      n = sendto(sockfd, buf, size, 0, &serv_addr, sizeof(serv_addr));
      if (n != size) break;
      // usleep(1000);

      struct pollfd pfd[1];
      pfd[0].fd = sockfd;
      pfd[0].events = POLLIN;
      int rv = poll(pfd, 1, 1); // wait for incoming packet or timeout

      // if there is incoming packet, recv it
      if(rv > 0){
        if(pfd[0].revents & POLLIN){
          n = recvfrom(sockfd, temp_buf, sizeof(temp_buf), 0, &serv_addr, sizeof(serv_addr));
        }
      }
    }
  }

  fclose(fp);
  close(sockfd);

  //Free memory
  if (buf) free(buf);

  return 0;
}

