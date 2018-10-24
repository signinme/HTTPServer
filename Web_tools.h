#ifndef _WEB_TOOLS
#define _WEB_TOOLS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <semaphore.h>
#include <fcntl.h>

#define WebTools_SHORT_BUF_SIZE 20
#define WebTools_STRING_SIZE 103

#define ILLEGAL -2
#define OVERFLOW -1
#define ERROR 0

typedef struct Web_Add
{
	int fd;
	struct sockaddr_in addr;
} WADDR, *WADDRP;

typedef struct SOCK
{
	int sock;
} SOCK, *SOCKP;

typedef struct Header_Line
{
	char head[WebTools_STRING_SIZE];
	char content[WebTools_STRING_SIZE];
} Header_Line;

/*******************************/
/* $begin rio_t */
#define RIO_BUFSIZE 8192
typedef struct {
    int rio_fd;                /* descriptor for this internal buf */
    int rio_cnt;               /* unread bytes in internal buf */
    char *rio_bufptr;          /* next unread byte in internal buf */
    char rio_buf[RIO_BUFSIZE]; /* internal buffer */
} rio_t;
/* $end rio_t */
/* Rio (Robust I/O) package */
ssize_t rio_readn(int fd, void *usrbuf, size_t n);
ssize_t rio_writen(int fd, void *usrbuf, size_t n);
void rio_readinitb(rio_t *rp, int fd); 
ssize_t	rio_readnb(rio_t *rp, void *usrbuf, size_t n);
ssize_t	rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen);

/*******************************/
/*
* basic functional functions
*/
void InitDaemon(void);
void error_handle(char *);
int msg_output_fd(int, char *);
int msg_line_output_fd(int, char *);
int msg_output_fp(FILE *, char *);
int msg_line_output_fp(FILE *, char *);
char *get_time(char *);
int get_file_size(char *);
char *strlocate(char *, char);
int tail_delete(char *);
int string_decode(char *);
/*******************************/
/*
* data structure 'Plan'
* data struct: queue
*/
typedef struct Plan
{
	char *buf;
	struct Plan *next;
} Plan;
typedef struct Plan_Details
{
	Plan *tail;
	int planlength;
} Plan_Details;

int PlanCreate(Plan *);
int PlanCheck(Plan *);
int PlanSize(Plan *, int *, int *);
int PlanIndexInsert(Plan *, char *, int);
int PlanTailInsert(Plan *, char *);
int PlanHeadPop(Plan *, char *);
int PlanHeadPeek(Plan *, char *);
int PlanTailPop(Plan *, char *);
int PlanLink(Plan *, Plan *);
int PlanLength(Plan *);
int PlanClean(Plan *);
void PlanDestroy(Plan *);
/*******************************/
/*
* identity
* struct Cookie and struct Identity
* data struct: list
*/
typedef struct Cookie
{
	char *name, *value;
} Cookie;
typedef struct Cookie_jar
{
	Cookie cookie;
	struct Cookie_jar *next;
} Cookie_jar;
typedef struct Identity
{
	char us_name[WebTools_SHORT_BUF_SIZE];
	char us_root_path[WebTools_STRING_SIZE];
	char us_IP[WebTools_SHORT_BUF_SIZE];
	char *identity;

	time_t last_time;
	struct Identity *next;
} Identity;

int Cookie_jar_Create(Cookie_jar *);
int Cookie_jar_Destroy(Cookie_jar *);
#endif