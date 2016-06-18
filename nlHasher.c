/*
Source: http://stackoverflow.com/questions/3299386/how-to-use-netlink-socket-to-communicate-with-a-kernel-module/3334782#3334782
*/

#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>


#define NETLINK_USER 31
#define MAX_PAYLOAD 1024 /* maximum payload size*/
// HASH RELATED
#define HASH_BUFFER_SIZE 64


void handle_requests(void);
void create_msg(struct msghdr * , struct sockaddr_nl *, char *);
char * calc_hash(char *);
void sha256_to_string(unsigned char [SHA256_DIGEST_LENGTH]);

char hash_str[HASH_BUFFER_SIZE+1];


struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec *iov;
int sock_fd;
struct msghdr msg;

int main()
{
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
    {
	    printf("ERROR !!!\n");
	    return -1;

    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */
    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    printf("[INFO] Kblocker hash calculator running.\n");
    handle_requests();
    close(sock_fd);
    return 0;
}

char * calc_hash(char * filename)
{
    printf("[INFO] Calculating hash for : %s\n", filename);

    unsigned char hash[60];

    int i;
    SHA256_CTX sha256;
    memset(hash, 0, 60);

    FILE* fd;
    fd = fopen(filename, "rb");

    if(!fd)
        return "goodbye";

    fseek(fd ,0, SEEK_END);
    int filesize = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    char* buffer = malloc(filesize+1);
    fread(buffer, 1, filesize, fd);

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, filesize);
    SHA256_Final(hash, &sha256);

    sha256_to_string(hash);

    free(buffer);

    return hash_str;
}

void sha256_to_string(unsigned char hash[SHA256_DIGEST_LENGTH])
{
    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        snprintf(&hash_str[i*2], SHA256_DIGEST_LENGTH, "%02x", (unsigned int)hash[i]);
    }
    hash_str[HASH_BUFFER_SIZE] = 0;
}


// struct sockaddr_nl src_addr, dest_addr;
// struct nlmsghdr *nlh = NULL;
// struct iovec iov;
// int sock_fd;
// struct msghdr msg;
void handle_requests(void)
{   

    printf("[INFO] Sending connection message to KBlocker.\n");
    create_msg(&msg, &dest_addr, "Init");
    sendmsg(sock_fd, &msg, 0);
    printf("[INFO] Awaiting hash to calculate ..\n");

    while(1)
    { 
        recvmsg(sock_fd, &msg, 0);
        char * filename = NLMSG_DATA((struct nlmsghdr *)(msg.msg_iov->iov_base));

        if( strncmp(filename , "terminate", 9) == 0)
            break;

        printf("[INFO] Received file to calcualte hash: %s\n", filename);
        char * hash = calc_hash(filename);
        printf("[INFO] sha256 for %s is (%s)\n", filename, hash);
        create_msg(&msg, &dest_addr, hash);
        sendmsg(sock_fd, &msg, 0);
    }
        
    // close(sock_fd);
}


// struct sockaddr_nl src_addr, dest_addr;
// struct nlmsghdr *nlh = NULL;
// struct iovec iov;
// int sock_fd;
// struct msghdr msg;

void create_msg(struct msghdr * message, struct sockaddr_nl * dest, char * data)
{
    nlh = (struct nlmsghdr *) malloc( NLMSG_SPACE(MAX_PAYLOAD));
    iov = (struct iovec *) malloc(sizeof(struct iovec));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strcpy(NLMSG_DATA(nlh), data);

    iov->iov_base = (void *)nlh;
    iov->iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
}