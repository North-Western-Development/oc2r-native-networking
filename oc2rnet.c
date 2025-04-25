#ifndef CLITEST
#include "li_cil_oc2_common_inet_DefaultSessionLayer.h"
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef CLITEST
#include <stdio.h>
#endif

#if defined(__linux__) || defined(__APPLE__)

#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define ICMP_HEADER_SIZE 8

static ssize_t doPing(uint32_t ip, size_t size, char *data, char *response,
                      uint32_t timeout) {
  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (sockfd < 0) {
#ifdef CLITEST
    perror("socket");
#endif
    return -1;
  }

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = ip,
  };

  size_t header_size =
#ifdef __linux__
      ICMP_HEADER_SIZE;
#else
      sizeof(struct icmp);
#endif
  size_t packet_size = size + ICMP_HEADER_SIZE;
  unsigned char *packet = malloc(packet_size);
  if (!packet) {
    close(sockfd);
    return -1;
  }

  struct icmp *icmp = (struct icmp *)packet;
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_id = getpid() & 0xFFFF;
  icmp->icmp_seq = 1;
  icmp->icmp_cksum = 0;
  memcpy(packet + ICMP_HEADER_SIZE, data, size);
  if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
#ifdef CLITEST
    perror("sendto");
#endif
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
#ifdef CLITEST
    perror("poll");
#endif
    free(packet);
    close(sockfd);
    return -1;
  } else if (poll_result == 0) {
#ifdef CLITEST
    fputs("Timed out\n", stderr);
#endif
    free(packet);
    close(sockfd);
    return -1;
  }

  unsigned char *recvbuf = calloc(size + header_size, 1);
  if (!recvbuf) {
    free(packet);
    close(sockfd);
  }
  ssize_t n = recvfrom(sockfd, recvbuf, size + header_size, 0, NULL, NULL);
  if (n < 0) {
#ifdef CLITEST
    perror("recvfrom");
#endif
    free(packet);
    free(recvbuf);
    close(sockfd);
    return -1;
  }

  memcpy(response, recvbuf + header_size, n - header_size);
  free(packet);
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
