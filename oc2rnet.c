#ifndef CLITEST
#include "li_cil_oc2_common_inet_DefaultSessionLayer.h"
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
static uint16_t checksum(void *b, int len) {
  uint16_t *buf = b;
  uint32_t sum = 0;

  for (; len > 1; len -= 2)
    sum += *buf++;
  if (len == 1)
    sum += *(uint8_t *)buf;

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}
#endif

#if defined(__linux__)

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

static ssize_t doPing(uint32_t ip, size_t size, char *data, char *response,
                      uint32_t timeout) {
  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (sockfd < 0) {
    return -1;
  }

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = ip,
  };

  size_t packet_size = sizeof(struct icmphdr) + size;
  unsigned char *packet = malloc(packet_size);
  if (!packet) {
    close(sockfd);
    return -1;
  }

  struct icmphdr *icmp = (struct icmphdr *)packet;
  icmp->type = ICMP_ECHO;
  icmp->code = 0;
  icmp->un.echo.id = getpid() & 0xFFFF;
  icmp->un.echo.sequence = 1;
  memcpy(packet + sizeof(struct icmphdr), data, size);
  icmp->checksum = 0;
  icmp->checksum = checksum(packet, packet_size);

  if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
    free(packet);
    close(sockfd);
    return -1;
  }

  struct pollfd pfd = {
      .fd = sockfd,
      .events = POLLIN,
  };

  int poll_result = poll(&pfd, 1, timeout);
  if (poll_result < 0) {
    free(packet);
    close(sockfd);
    return -1;
  } else if (poll_result == 0) {
    free(packet);
    close(sockfd);
    return -1;
  }

  unsigned char *recvbuf = calloc(size + sizeof(struct icmphdr), 1);
  if (!recvbuf) {
    free(packet);
    close(sockfd);
  }
  ssize_t n =
      recvfrom(sockfd, recvbuf, size + sizeof(struct icmphdr), 0, NULL, NULL);
  if (n < 0) {
    free(packet);
    free(recvbuf);
    close(sockfd);
    return -1;
  }

  memcpy(response, recvbuf + sizeof(struct icmphdr),
         n - sizeof(struct icmphdr));
  free(packet);
  free(recvbuf);
  close(sockfd);
  return n - sizeof(struct icmphdr);
}

#elif defined(_WIN32)

#include <winsock2.h>

#include <iphlpapi.h>
#include <ws2tcpip.h>

#include <icmpapi.h>

static ssize_t doPing(uint32_t ip, size_t size, char *data, char *response,
                      uint32_t timeout) {
  IPAddr ip_addr = ip;

  HANDLE hIcmp = IcmpCreateFile();
  if (hIcmp == INVALID_HANDLE_VALUE)
    return -1;

  DWORD replySize = sizeof(ICMP_ECHO_REPLY) + size;
  void *replyBuffer = malloc(replySize);
  if (!replyBuffer) {
    IcmpCloseHandle(hIcmp);
    return -1;
  }

  DWORD ret = IcmpSendEcho(hIcmp, ip_addr, data, (WORD)size, NULL, replyBuffer,
                           replySize, timeout);

  ssize_t result = -1;
  if (ret > 0) {
    PICMP_ECHO_REPLY echoReply = (PICMP_ECHO_REPLY)replyBuffer;
    DWORD bytesReceived = echoReply->DataSize;
    if (bytesReceived > size)
      bytesReceived = (DWORD)size;
    memcpy(response, echoReply->Data, bytesReceived);
    result = bytesReceived;
  }

  free(replyBuffer);
  IcmpCloseHandle(hIcmp);
  return result;
}

#elif defined(__APPLE__)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static ssize_t doPing(uint32_t ip, size_t size, char *data, char *response,
                      uint32_t timeout) {
  int sockfd;
  struct sockaddr_in dest_addr = {0};
  unsigned char sendbuf[1024];
  unsigned char recvbuf[1024];
  struct icmp *icmp_hdr;
  ssize_t sent_bytes, recv_bytes;
  socklen_t addrlen = sizeof(dest_addr);
  struct timeval tv;

  if (size > sizeof(sendbuf) - sizeof(struct icmp))
    size = sizeof(sendbuf) - sizeof(struct icmp);

  // Create socket
  sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (sockfd < 0)
    return -1;

  // Set timeout
  tv.tv_sec = timeout / 1000;
  tv.tv_usec = (timeout % 1000) * 1000;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

  // Prepare destination address
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = ip;

  // Build ICMP echo request
  icmp_hdr = (struct icmp *)sendbuf;
  icmp_hdr->icmp_type = ICMP_ECHO;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->icmp_id = getpid() & 0xFFFF;
  icmp_hdr->icmp_seq = 0;
  memcpy(icmp_hdr->icmp_data, data, size);
  int packet_size = sizeof(struct icmp) + size;
  icmp_hdr->icmp_cksum = 0;
  icmp_hdr->icmp_cksum = checksum((uint16_t *)icmp_hdr, packet_size);

  // Send
  sent_bytes = sendto(sockfd, sendbuf, packet_size, 0,
                      (struct sockaddr *)&dest_addr, sizeof(dest_addr));
  if (sent_bytes < 0) {
    close(sockfd);
    return -1;
  }

  // Receive
  recv_bytes = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
  if (recv_bytes < 0) {
    close(sockfd);
    return -1;
  }

  // Extract ICMP header from IP packet
  struct ip *ip_hdr = (struct ip *)recvbuf;
  int ip_hdr_len = ip_hdr->ip_hl << 2;

  if (recv_bytes < ip_hdr_len + sizeof(struct icmp)) {
    close(sockfd);
    return -1;
  }

  struct icmp *recv_icmp = (struct icmp *)(recvbuf + ip_hdr_len);
  if (recv_icmp->icmp_type != ICMP_ECHOREPLY ||
      recv_icmp->icmp_id != icmp_hdr->icmp_id) {
    close(sockfd);
    return -1;
  }

  // Copy response data
  size_t data_len = recv_bytes - ip_hdr_len - sizeof(struct icmp);
  if (data_len > size)
    data_len = size;
  memcpy(response, recv_icmp->icmp_data, data_len);

  close(sockfd);
  return data_len;
}

#else
#error platform not supported
#endif

#ifdef CLITEST

int main(void) {
  char ip[4];
  ip[0] = 1;
  ip[1] = 1;
  ip[2] = 1;
  ip[3] = 1;
  char data[64];
  char newdata[sizeof(data)];
  memset(data, 0x69, sizeof(data));
  memset(newdata, 0, sizeof(newdata));
  ssize_t ret = doPing(*(uint32_t *)ip, 64, data, newdata, 1000);
  if (ret == -1) {
    puts("Ping failed!");
    return 1;
  }
  printf("got back %zd bytes\n", ret);
  FILE *file = fopen("pingout", "w");
  fwrite(newdata, 1, sizeof(newdata), file);
  fclose(file);
  return 0;
}

#else

JNIEXPORT jbyteArray JNICALL
Java_li_cil_oc2_common_inet_DefaultSessionLayer_sendICMP(
    JNIEnv *env, jobject obj, jbyteArray ip, jbyteArray data, jint size,
    jint timeout) {
  (void)obj;
  jbyte *olddata = (*env)->GetByteArrayElements(env, data, NULL);
  jbyte *addr = (*env)->GetByteArrayElements(env, ip, NULL);
  jbyte *response = calloc(size, 1);
  if (!response)
    fprintf(stderr, "[OC2R-network]: malloc failed\n");

  ssize_t retsize = doPing(*(uint32_t *)addr, size, olddata, response, timeout);
  if (retsize == -1)
    return NULL;

  jbyteArray ret = (*env)->NewByteArray(env, retsize);
  (*env)->SetByteArrayRegion(env, ret, 0, retsize, (const jbyte *)response);
  free(response);
  (*env)->ReleaseByteArrayElements(env, data, olddata, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, ip, addr, JNI_ABORT);
  if (!ret)
    return NULL;
  return ret;
}

#endif
