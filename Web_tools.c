#include "Web_tools.h"

/*******************************/
/*
* basic functional functions
*/
void InitDaemon(void)
{
    pid_t pid = 0;

    if ((pid = fork()) != 0)
    {
        exit(0);
    }

    setsid(); 

    signal(SIGINT,  SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
    // ignore_pipe();

    if ((pid = fork()) != 0)
    {
        exit(0);
    }

    umask(0);
}
void error_handle(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	fflush(stderr);
	exit(1);
}

int msg_output_fd(int fd, char *msg)
{
	rio_writen(fd, msg, strlen(msg));
	return 1;
}
int msg_line_output_fd(int fd, char *msg)
{
	rio_writen(fd, msg, strlen(msg));
	rio_writen(fd, "\n", 1);
	return 1;
}
int msg_output_fp(FILE *fp, char *msg)
{
	fprintf(fp, "%s", msg);
	fflush(fp);
	return 1;
}
int msg_line_output_fp(FILE *fp, char *msg)
{
	fprintf(fp, "%s\n", msg);
	fflush(fp);
	return 1;
}
char *get_time(char *buf)
{
	static char sbuf[WebTools_STRING_SIZE];
	char *bufp = buf ? buf : sbuf;
	time_t t;
	time(&t);
	struct tm *tt;
	tt = localtime(&t);
	sprintf(bufp, "%d-%d-%d %d:%d:%d", tt->tm_year + 1900, tt->tm_mon + 1, tt->tm_mday, tt->tm_hour, tt->tm_min, tt->tm_sec);
	return bufp;
}

int get_file_size(char *path)
{
	int file_size = -1;
	struct stat statbuff;
	if(stat(path, &statbuff) >= 0)
		file_size = statbuff.st_size;
	return file_size;
}

char *strlocate(char *buf, char c)
{
	static char *str;
	if(!buf)
	{

		if(!str)
			return NULL;
	}
	else
		str = buf;
	while(*str && *str != c)
		str ++;
	return str;
}
int tail_delete(char *buf)
{
	char *p = buf + strlen(buf) - 1;
	while(p >= buf && *p && (*p == '\r' || *p == '\n'))
	{
		*p = '\0';
		p --;
	}
	return 1;
}
int string_decode(char *buf)
{
	char str[WebTools_STRING_SIZE], *s = str;
	char *p = buf;
	int num, tmp;
	while(*p)
	{
		if(*p == '%')
		{
			p ++;
			if(*p >= '0' && *p <= '9')
				tmp = *p - '0';
			else if(*p >= 'a' && *p <= 'z')
				tmp = *p - 'a' + 10;
			else if(*p >= 'A' && *p <= 'Z')
				tmp = *p - 'A' + 10;
			num = tmp;
			p ++;
			if(*p >= '0' && *p <= '9')
				tmp = *p - '0';
			else if(*p >= 'a' && *p <= 'z')
				tmp = *p - 'a' + 10;
			else if(*p >= 'A' && *p <= 'Z')
				tmp = *p - 'A' + 10;
			p ++;
			num = num * 16 + tmp;
			*(s ++) = num;
		}
		else if(*p == '+')
		{
			p ++;
			*(s ++) = ' ';
		}
		else
			*(s ++) = *(p ++);
	}
	*s = '\0';
	strcpy(buf, str);
	return 1;
}
/****************************/
/*
* functions of struct 'OPlan'
*/

int PlanCreate(Plan *plan)
{
	plan->buf = (char*)malloc(sizeof(Plan_Details));
	if(!plan->buf)
		return OVERFLOW;
	((Plan_Details*)plan->buf)->tail = plan;
	((Plan_Details*)plan->buf)->planlength = 0;
	plan->next = NULL;
	return 1;
}
int PlanCheck(Plan *plan)
{
	if(plan->buf)
		return 1;
	return ERROR;
}
int PlanSize(Plan *plan, int *_length, int *_num)
{
	int length = 0, num = 0;
	Plan *p = plan->next;
	while(p)
	{
		num ++;
		length += strlen(p->buf);
		p = p->next;
	}
	if(_length)
		*_length = length;
	if(_num)
		*_num = num;
	return 1;
}
int PlanIndexInsert(Plan *plan, char *buf, int index)
{
	char buft[1] = "\0", *bufp;
	bufp = buf ? buf : buft;

	int i = 1;
	Plan *t = plan;
	while(t && i < index)
	{
		i ++;
		t = t->next;
	}
	if(t)
	{
		Plan *tmp = (Plan*)malloc(sizeof(Plan));
		if(!tmp)
			return OVERFLOW;
		tmp->buf = (char*)malloc(sizeof(char) * (strlen(buf) + 1));
		if(!tmp->buf)
		{
			free(tmp);
			return OVERFLOW;
		}
		strcpy(tmp->buf, bufp);
		tmp->next = t->next;
		t->next = tmp;

		if(!tmp->next)
			((Plan_Details*)(plan->buf))->tail = tmp;
		return 1;
	}
	else
	{
		return ERROR;
	}
}
int PlanTailInsert(Plan *plan, char *buf)
{
	char buft[1] = "\0", *bufp;
	bufp = buf ? buf : buft;

	Plan *tail = ((Plan_Details*)(plan->buf))->tail;
	int length = strlen(bufp);

	tail->next = (Plan*)malloc(sizeof(Plan));
	if(!tail->next)
		return OVERFLOW;
	tail->next->buf = (char *)malloc(sizeof(char) * (length + 1));
	if(!tail->next->buf)
		return OVERFLOW;
	tail = tail->next;
	tail->next = NULL;
	memcpy(tail->buf, bufp, length);
	tail->buf[length] = '\0';
	
	((Plan_Details*)plan->buf)->tail = tail;
	return 1;
}
int PlanHeadPop(Plan *plan, char *buf)
{
	if(!plan->next)
		return ERROR;
	Plan *tmp = plan->next->next;

	if(buf)
		strcpy(buf, plan->next->buf);

	free(plan->next->buf);
	free(plan->next);

	plan->next = tmp;
	if(!tmp)
		((Plan_Details*)plan->buf)->tail = plan;
	return 1;
}
int PlanHeadPeek(Plan *plan, char *buf)
{
	if(!plan->next)
		return ERROR;
	if(buf)
		strcpy(buf, plan->next->buf);
	return 1;
}
int PlanTailPop(Plan *plan, char *buf)
{
	if(!plan->next)
		return ERROR;

	Plan *tail = plan;
	while(tail->next->next != NULL)
		tail = tail->next;

	if(buf)
		strcpy(buf, tail->next->buf);
	free(tail->next->buf);
	free(tail->next);
	tail->next = NULL;
	((Plan_Details*)(plan->buf))->tail = tail;
	return 1;
}
int PlanLink(Plan *plan, Plan *para)
{
	if(para->next && para->next != para)
	{
		((Plan_Details*)plan->buf)->tail->next = para->next;
		((Plan_Details*)plan->buf)->tail = ((Plan_Details*)para->buf)->tail;
		((Plan_Details*)para->buf)->tail = para;
		para->next = NULL;
	}
	return 1;
}
int PlanLength(Plan *plan)
{
	int length = 0;
	Plan *p = plan->next;
	while(p)
	{
		length += strlen(p->buf);
		p = p->next;
	}
	return length;
}
int PlanClean(Plan *plan)
{
	Plan *p = plan->next;
	while(p)
	{
		Plan *tmp = p->next;
		free(p->buf);
		free(p);
		p = tmp;
	}
	((Plan_Details*)(plan->buf))->tail = plan;
	((Plan_Details*)(plan->buf))->planlength = 0;
	plan->next = NULL;
	return 1;
}
void PlanDestroy(Plan *plan)
{
	Plan *p = plan->next;
	free(plan->buf);
	while(p)
	{
		Plan *tmp = (p->next);
		free(p->buf);
		free(p);
		p = tmp;
	}
	plan->buf = NULL;
	plan->next = NULL;
	return;
}

/*****************************/
/*********************************************************************
 * The Rio package - robust I/O functions
 **********************************************************************/
/*
 * rio_readn - robustly read n bytes (unbuffered)
 */
/* $begin rio_readn */
ssize_t rio_readn(int fd, void *usrbuf, size_t n) 
{
    size_t nleft = n;
    ssize_t nread;
    char *bufp = usrbuf;

    while (nleft > 0) {
	if ((nread = read(fd, bufp, nleft)) < 0) {
	    if (errno == EINTR) /* interrupted by sig handler return */
		nread = 0;      /* and call read() again */
	    else
		return -1;      /* errno set by read() */ 
	} 
	else if (nread == 0)
	    break;              /* EOF */
	nleft -= nread;
	bufp += nread;
    }
    return (n - nleft);         /* return >= 0 */
}
/* $end rio_readn */

/*
 * rio_writen - robustly write n bytes (unbuffered)
 */
/* $begin rio_writen */
ssize_t rio_writen(int fd, void *usrbuf, size_t n) 
{
    size_t nleft = n;
    ssize_t nwritten;
    char *bufp = usrbuf;

    while (nleft > 0) {
	if ((nwritten = write(fd, bufp, nleft)) <= 0) {
	    if (errno == EINTR)  /* interrupted by sig handler return */
		nwritten = 0;    /* and call write() again */
	    else
		return -1;       /* errno set by write() */
	}
	nleft -= nwritten;
	bufp += nwritten;
    }
    return n;
}
/* $end rio_writen */


/* 
 * rio_read - This is a wrapper for the Unix read() function that
 *    transfers min(n, rio_cnt) bytes from an internal buffer to a user
 *    buffer, where n is the number of bytes requested by the user and
 *    rio_cnt is the number of unread bytes in the internal buffer. On
 *    entry, rio_read() refills the internal buffer via a call to
 *    read() if the internal buffer is empty.
 */
/* $begin rio_read */
static ssize_t rio_read(rio_t *rp, char *usrbuf, size_t n)
{
    int cnt;

    while (rp->rio_cnt <= 0) {  /* refill if buf is empty */
	rp->rio_cnt = read(rp->rio_fd, rp->rio_buf, 
			   sizeof(rp->rio_buf));
	if (rp->rio_cnt < 0) {
	    if (errno != EINTR) /* interrupted by sig handler return */
		return -1;
	}
	else if (rp->rio_cnt == 0)  /* EOF */
	    return 0;
	else 
	    rp->rio_bufptr = rp->rio_buf; /* reset buffer ptr */
    }

    /* Copy min(n, rp->rio_cnt) bytes from internal buf to user buf */
    cnt = n;          
    if (rp->rio_cnt < n)   
	cnt = rp->rio_cnt;
    memcpy(usrbuf, rp->rio_bufptr, cnt);
    rp->rio_bufptr += cnt;
    rp->rio_cnt -= cnt;
    return cnt;
}
/* $end rio_read */

/*
 * rio_readinitb - Associate a descriptor with a read buffer and reset buffer
 */
/* $begin rio_readinitb */
void rio_readinitb(rio_t *rp, int fd) 
{
    rp->rio_fd = fd;  
    rp->rio_cnt = 0;  
    rp->rio_bufptr = rp->rio_buf;
}
/* $end rio_readinitb */

/*
 * rio_readnb - Robustly read n bytes (buffered)
 */
/* $begin rio_readnb */
ssize_t rio_readnb(rio_t *rp, void *usrbuf, size_t n) 
{
    size_t nleft = n;
    ssize_t nread;
    char *bufp = usrbuf;
    
    while (nleft > 0) {
	if ((nread = rio_read(rp, bufp, nleft)) < 0) {
	    if (errno == EINTR) /* interrupted by sig handler return */
		nread = 0;      /* call read() again */
	    else
		return -1;      /* errno set by read() */ 
	} 
	else if (nread == 0)
	    break;              /* EOF */
	nleft -= nread;
	bufp += nread;
    }
    return (n - nleft);         /* return >= 0 */
}
/* $end rio_readnb */

/* 
 * rio_readlineb - robustly read a text line (buffered)
 */
/* $begin rio_readlineb */
ssize_t rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen) 
{
  int n, rc;
    char c, *bufp = usrbuf;

    for (n = 1; n < maxlen; n++) { 
    if ((rc = rio_read(rp, &c, 1)) == 1) {
        *bufp++ = c;
        if (c == '\n')
        break;
    } else if (rc == 0) {
        if (n == 1)
        return 0; /* EOF, no data read */
        else
        break;    /* EOF, some data was read */
    } else
        return -1;    /* error */
    }
    *bufp = 0;
    return n;  
}
/* $end rio_readlineb */
/*******************************/
/*
* Cookie & Cookie_jar
* data struct: list
*/
int Cookie_jar_Create(Cookie_jar *cj)
{
	// *((int*)cj->cookie.name) = 0;
	cj->next = NULL;
	return 1;
}
int Cookie_jar_Destroy(Cookie_jar *cj)
{
	Cookie_jar *cjp = cj->next;
	while(cjp)
	{
		Cookie_jar *tmp = cjp->next;
		free(cjp->cookie.name);
		free(cjp->cookie.value);
		free(cjp);
		cjp = tmp;
	}
	cj->next = NULL;
	// *((int*)cj->cookie.name) = -1;
	return 1;
}
