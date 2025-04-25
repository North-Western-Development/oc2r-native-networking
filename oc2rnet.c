#ifndef CLITEST
#include "li_cil_oc2_common_inet_DefaultSessionLayer.h"
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef CLITEST
#include <stdio.h>
#endif

static void cliprinterr(const char *str) {
#ifdef CLITEST
  fputs(str, stderr);
#endif
}

#if defined(__linux__) || defined(__APPLE__)

#ifndef __linux__
static uint16_t checksum(void *b, size_t len) {
  uint16_t *buf = b;
  uint32_t sum = 0;

  for (; len > 1; len -= 2)
    sum += *buf++;
  if (len == 1)
    sum += *(uint8_t *)buf;

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return ~sum;
}
#endif

#include <sys/types.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define ICMP_HEADER_SIZE 8

static void cliperror(const char *str) {
#ifdef CLITEST
  perror(str);
#endif
}

static ssize_t doPing(uint32_t ip, size_t size, char *data, char *response,
                      uint32_t timeout) {
  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (sockfd < 0) {
    cliperror("socket");
    return -1;
  }

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = ip,
  };

  size_t packet_size = size + ICMP_HEADER_SIZE;
  struct icmp *packet = malloc(packet_size);
  if (!packet) {
    cliprinterr("malloc failed\n");
    close(sockfd);
    return -1;
  }

  packet->icmp_type = ICMP_ECHO;
  packet->icmp_code = 0;
  packet->icmp_id = getpid() & 0xFFFF;
  packet->icmp_seq = 1;
  memcpy(packet->icmp_data, data, size);
#ifndef __linux__ // Linux ignores and recalculates the checksum for us
  packet->icmp_cksum = 0;
  packet->icmp_cksum = checksum(packet, packet_size);
#endif

  if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
    cliperror("sendto");
    free(packet);
    close(sockfd);
    return -1;
  }
  free(packet);

  struct pollfd pfd = {
      .fd = sockfd,
      .events = POLLIN,
  };

  int poll_result = poll(&pfd, 1, timeout);
  if (poll_result < 0) {
    cliperror("poll");
    close(sockfd);
    return -1;
  } else if (poll_result == 0) {
    cliprinterr("Timed out\n");
    close(sockfd);
    return -1;
  }

  size_t header_size =
#ifdef __linux__
      ICMP_HEADER_SIZE;
#else
      sizeof(struct icmp);
#endif
  unsigned char *recvbuf = malloc(size + header_size);
  if (!recvbuf) {
    cliprinterr("malloc failed\n");
    close(sockfd);
    return -1;
  }
  ssize_t n = recvfrom(sockfd, recvbuf, size + header_size, 0, NULL, NULL);
  if (n < 0) {
    cliperror("recvfrom");
    free(recvbuf);
    close(sockfd);
    return -1;
  }

  memcpy(response, recvbuf + header_size, n - header_size);
  free(recvbuf);
  close(sockfd);
  return n - header_size;
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
  if (hIcmp == INVALID_HANDLE_VALUE) {
#ifdef CLITEST
    fprintf(stderr, "IcmpCreateFile failed with error %ld\n", GetLastError());
#endif
    return -1;
  }

  DWORD replySize = sizeof(ICMP_ECHO_REPLY) + size;
  void *replyBuffer = malloc(replySize);
  if (!replyBuffer) {
    cliprinterr("malloc failed\n");
    IcmpCloseHandle(hIcmp);
    return -1;
  }

  DWORD ret = IcmpSendEcho(hIcmp, ip_addr, data, (WORD)size, NULL, replyBuffer,
                           replySize, timeout);

  ssize_t result = -1;
  if (ret > 0) {
    PICMP_ECHO_REPLY echoReply = (PICMP_ECHO_REPLY)replyBuffer;
    size_t bytesReceived = echoReply->DataSize;
    if (bytesReceived > size)
      bytesReceived = size;
    memcpy(response, echoReply->Data, bytesReceived);
    result = bytesReceived;
  }
#ifdef CLITEST
  else {
    DWORD error = GetLastError();
    if (error == 11010)
      fprintf(stderr, "Timed out\n");
    else
      fprintf(stderr, "IcmpCreateFile failed with error %ld\n", error);
  }
#endif

  free(replyBuffer);
  IcmpCloseHandle(hIcmp);
  return result;
}

#else
#error platform not supported
#endif

#ifdef CLITEST

#include <stdio.h>

#ifndef PACKET_SIZE
#define PACKET_SIZE 64
#endif

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("usage: %s <ip>\n", argv[0]);
    return 1;
  }

  char ip[4];
  sscanf(argv[1], "%hhu.%hhu.%hhu.%hhu\n", ip, ip + 1, ip + 2, ip + 3);
  printf("Pinging %hhu.%hhu.%hhu.%hhu\n", ip[0], ip[1], ip[2], ip[3]);
  char *data = malloc(PACKET_SIZE);
  char *newdata = malloc(PACKET_SIZE);
  memset(data, 0x69, PACKET_SIZE);
  memset(newdata, 0, PACKET_SIZE);
  ssize_t ret = doPing(*(uint32_t *)ip, PACKET_SIZE, data, newdata, 1000);
  if (ret == -1) {
    puts("Ping failed!");
    return 1;
  }
  printf("got back %zd bytes\n", ret);
  FILE *file = fopen("pingout", "w");
  fwrite(newdata, 1, PACKET_SIZE, file);
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
    return NULL;

  ssize_t retsize = doPing(*(uint32_t *)addr, size, (char *)olddata,
                           (char *)response, timeout);
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
