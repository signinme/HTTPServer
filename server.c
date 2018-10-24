#include "Web_tools.h"

#define BUF_SIZE 100
#define LONG_BUF_SIZE 1024
#define SEND_MSG_SIZE 1048576

Identity ID_list;
void *ID_list_tranverse(void*);
/******************************/
void *pthread(void *);
void request_handle(WADDR *clientaddr);
int request_GET(int, char *, char *, const Identity *, int, char *);
int request_POST(int, rio_t *, char *, char *, size_t, Identity *);
int request_LOGIN(int);
int request_REMOVE(char *, Identity *);
int request_MKDIR(char *, Identity *);
/******************************/
/*
* tools
*/
void fill_header_line(Header_Line *, char *);
int file_path_split(char *, char *, char *);
char *fill_file_type(char *, char *);
int fill_cookie_jar(char *, Cookie_jar *);
int get_login_details(char *, char *, char *);
int login(char *, char *, char *, Identity **);
int logout(char *);
int identify(Cookie_jar *, Identity **);
int password_encode(char *, char *);
int cookie_value_rand(char *);
int send_message_plan(int, Plan, char *);
int send_message_buf(int, char *, int);
/*****************************/
/*
* Plan generator
*/
int header_sender(int, char *, char *, char *);
int plangenerator(Plan *, Plan *, char *, char *, char *);

char *default_root_path = "root_path/";

static sem_t Sem_fill_file_type;
static sem_t Sem_get_time;
static sem_t Sem_ID_list;
static sem_t Sem_ctime;

int main(int argc, char **argv)
{
	// InitDaemon();
	srand((unsigned)time(NULL));
	if(argc != 2)
	{
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
	}
	pthread_t t_id;
	SOCK sock;
	WADDR serveraddr;
	char buf[BUF_SIZE];

	sock.sock = socket(AF_INET, SOCK_STREAM, 0);
	memset(&serveraddr.addr, 0, sizeof(serveraddr.addr));
	serveraddr.addr.sin_family = AF_INET;
	serveraddr.addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.addr.sin_port = htons(atoi(argv[1]));

	if(bind(sock.sock, (struct sockaddr*)&serveraddr.addr, sizeof(serveraddr.addr)) == -1)
		error_handle("in 'main': function error: 'bind()' error");

	if(listen(sock.sock, 5) == -1)
		error_handle("in 'main': function error: 'listen()' error");

	// initialize Sem
	sem_init(&Sem_get_time, 0, 1);
	sem_init(&Sem_fill_file_type, 0, 1);
	sem_init(&Sem_ID_list, 0, 1);
	sem_init(&Sem_ctime, 0, 1);

	ID_list.next = (Identity*)malloc(sizeof(Identity));
	if(!ID_list.next)
	{
		exit(1);
	}

	ID_list.next = NULL;

	pthread_create(&t_id, NULL, ID_list_tranverse, NULL);
	msg_output_fp(stdout, get_time(NULL));
	msg_output_fp(stdout, ": Server Initialize Completed\n");
	// msg_output_fp(stdout, "Waiting to connent ...\n");

	sprintf(buf, "root_path/diary/%soutdiary.log", get_time(NULL));
	freopen(buf, "w", stdout);
	sprintf(buf, "root_path/diary/%serrdiary.log", get_time(NULL));
	freopen(buf , "w", stderr);

	sprintf(buf, "Server restart at %s", get_time(NULL));
	
	msg_line_output_fp(stdout, buf);
	while(1)
	{
		WADDRP clientaddrp = (WADDRP)malloc(sizeof(WADDR));
		if(!clientaddrp)
		{
			msg_output_fp(stderr, "in 'main': function error: 'malloc()' error\n");
			continue;
		}

		int clientaddr_size = sizeof(clientaddrp->addr);
		if((clientaddrp->fd = accept(sock.sock, (struct sockaddr*)&clientaddrp->addr, &clientaddr_size)) == -1)
		{
			msg_output_fp(stderr, "in 'main': function error: 'accept()' error\n");
			continue;
		}
		
		pthread_create(&t_id, NULL, pthread, (void*)clientaddrp);
	}

	close(sock.sock);

	sem_destroy(&Sem_get_time);
	sem_destroy(&Sem_fill_file_type);
	sem_destroy(&Sem_ctime);
	return 0;
}

void *ID_list_tranverse(void *para)
{
	pthread_detach(pthread_self());
	while(1)
	{
		sem_wait(&Sem_ID_list);
		Identity *id = &ID_list;
		
		while(id && id->next)
		{
			time_t now;
			time(&now);
			if(now - id->next->last_time > 900)
			{
				char buf[BUF_SIZE];
				sem_wait(&Sem_get_time);
				sprintf(buf, "%s:%s(%s) logout", get_time(NULL), id->next->us_name, id->next->us_IP);
				sem_post(&Sem_get_time);
				msg_line_output_fp(stdout, buf);

				Identity *tmp = id->next->next;
				free(id->next->identity);
				free(id->next);
				id->next = tmp;
			}
			id = id->next;
		}
		
		sem_post(&Sem_ID_list);
		sleep(300);
	}
}
/***********************************/
void *pthread(void *para)
{
	pthread_detach(pthread_self());

	WADDR clientaddr = *(WADDRP)para;
	free(para);
	char buf[BUF_SIZE];

	request_handle(&clientaddr);

	close(clientaddr.fd);
	return NULL;
}

void request_handle(WADDR *clientaddr)
{
	char buf[BUF_SIZE], lbuf[LONG_BUF_SIZE];
	char URL[BUF_SIZE] = {0}, httpversion[BUF_SIZE] = {0}, root_path[BUF_SIZE] = {0};
	char IP[BUF_SIZE]; int post;
	char us_name[BUF_SIZE], us_password[BUF_SIZE];
	char form_type[BUF_SIZE] = {0};
	char boundary[BUF_SIZE] = {0};
	char cookie_value[BUF_SIZE] = {0}, cookie_msg[BUF_SIZE] = {0};
	int download_flag = 0;
	Header_Line header;
	Identity *id = NULL;
	int request_length, result = 400;

	int content_length = 0;
	Cookie_jar cookie_jar;
	Cookie_jar_Create(&cookie_jar);
	
	rio_t riofd;
	rio_readinitb(&riofd, clientaddr->fd);

	strcpy(IP, inet_ntoa(clientaddr->addr.sin_addr));
	post = ntohs(clientaddr->addr.sin_port);
	if((request_length = rio_readlineb(&riofd, buf, BUF_SIZE)) <= 0)
	{
		strcpy(buf, "Unknow request");
		result = 400;
	}
	else
	{
		tail_delete(buf);
		fill_header_line(&header, buf);
	}

	sem_wait(&Sem_get_time);
	msg_output_fp(stdout, get_time(NULL));
	sem_post(&Sem_get_time);

	sprintf(lbuf, ": (%s:%d): %s", IP, post, buf);
	msg_line_output_fp(stdout, lbuf);

	while(request_length > 0 && rio_readlineb(&riofd, lbuf, LONG_BUF_SIZE) > 0)
	{
		tail_delete(lbuf);
		if(!memcmp(lbuf, "Content-Length:", 15))
			content_length = atoi(lbuf + 15);
		if(!memcmp(lbuf, "Content-Type", 12))
		{
			char *p = lbuf + 12;
			while(p < lbuf + strlen(lbuf) - 9)
			{
				if(!memcmp(p, "boundary=", 9))
				{
					strcpy(boundary, p + 9);
					strcpy(form_type, "form_type=up&");
					break;
				}
				p ++;
			}
		}
		if(!memcmp(lbuf, "Cookie:", 7))
		{
			fill_cookie_jar(lbuf + 7, &cookie_jar);
		}
		if(!*lbuf)
			break;
	}
	if(request_length > 0)
	{
		char *p = header.content;
		while(*p != ' ') p ++;
		memcpy(URL, header.content, p - header.content);
		URL[p - header.content] = '\0';
		strcpy(p + 1, httpversion);

		string_decode(URL);
		if(!strcmp(header.head, "POST") && !*form_type)
		{
			rio_readlineb(&riofd, form_type, 14);
			tail_delete(form_type);
			if(!strcmp(form_type, "form_type=01&"))
			{
				rio_readlineb(&riofd, buf, content_length - 12);
				tail_delete(buf);
				if(get_login_details(buf, us_name, us_password))
				{
					if(login(us_name, us_password, IP, &id))
					{
						sprintf(cookie_msg, "Set-Cookie:identity=%s; Max-Age=900; Path = /; httponly\r\n", id->identity);
						strcpy(header.head, "GET");
					}
				}
			}

		}
		if(!id)
			identify(&cookie_jar, &id);

		if(!id)
		{
			result = request_LOGIN(clientaddr->fd);
			// request_GET(clientaddr->fd, "/login.html", "HTTP/1.1", ID_list.next, 0, NULL);
		}
		else
		{
			if(!strcmp(header.head, "POST") && *URL)
			{
				if(!strcmp(form_type, "form_type=up&"))
				{
					if((result = request_POST(clientaddr->fd, &riofd, URL, boundary, content_length, id)) == 202)
						strcpy(header.head, "GET");
				}
				if(!strcmp(form_type, "form_type=out"))
				{
					logout(id->us_name);
					result = request_LOGIN(clientaddr->fd);
				}
				
				if(!strcmp(form_type, "form_type=rm&"))
				{
					rio_readlineb(&riofd, buf, content_length - 12);
					tail_delete(buf);
					string_decode(buf);

					char *p = buf + 10;
					while(*p != '\0' && *p != '&')
						p ++;
					*p = '\0';
					char fn[LONG_BUF_SIZE];
					sprintf(fn, "%s%s", URL, buf + 10);
					
					if(request_REMOVE(fn, id) == 202)
						strcpy(header.head, "GET");
					else
						header_sender(clientaddr->fd, "400 Bad Request", URL, "ERROR");

				}
				if(!strcmp(form_type, "form_type=md&"))
				{
					rio_readlineb(&riofd, buf, content_length - 12);
					tail_delete(buf);
					string_decode(buf);

					if(buf[strlen(buf) - 1] != '/')
						strcat(buf, "/");

					char *p = buf + 10;
					while(*p != '\0' && *p != '&')
						p ++;
					*p = '\0';
					char fn[LONG_BUF_SIZE];
					sprintf(fn, "%s%s", URL, buf + 10);
					
					if(request_MKDIR(fn, id) == 202)
						strcpy(header.head, "GET");
					else
						header_sender(clientaddr->fd, "400 Bad Request", URL, "ERROR");

				}
				
			}
			if(!strcmp(header.head, "GET") && *URL)
			{
				result = request_GET(clientaddr->fd, URL, httpversion, id, download_flag, cookie_msg);
			}
			
		}
	}
	else
	{
		// header_sender(clientaddr->fd, "400 Bad Request", NULL, "");
	}

	sprintf(lbuf, "(%s:%d): %d-", IP, post, result);
	msg_line_output_fp(stdout, lbuf);

	Cookie_jar_Destroy(&cookie_jar);
	return;
}

int request_GET(int fd, char *URL, char *httpversion, const Identity *id, int download_flag, char *cookie_msg)
{
	if(!id)
	{
		return ERROR;
	}
	char file_path[BUF_SIZE], file_name[BUF_SIZE];
	char buf[LONG_BUF_SIZE], lbuf[LONG_BUF_SIZE];
	FILE *file; int filefd;
	int result;

	Plan message;
	Plan content;
	message.buf = content.buf = NULL;

	int file_size;
	char *filep = NULL;

	PlanCreate(&message);
	
	if(file_path_split(URL, file_path, file_name) == 1) // corrected URL
	{
		char Uspath[BUF_SIZE], UsURL[BUF_SIZE];
		strcpy(Uspath, id->us_root_path);
		if(*file_path)
		{
			strcat(Uspath, file_path);
		}
		sprintf(UsURL, "%s%s", Uspath, file_name);

		if(UsURL[strlen(UsURL) - 1] == '/') // directory
		{
			DIR *dirp;
			if((dirp = opendir(UsURL)) == NULL) // 404 no found
			{
				result = 404;
				PlanCreate(&content);
				plangenerator(&message, &content, "404 Not Found", file_path, "");
			}
			else
			{
				Plan file, dir;
				PlanCreate(&content);
				PlanCreate(&file);
				PlanCreate(&dir);

				result = 200;
				PlanTailInsert(&message, "HTTP/1.1 200 OK\r\n");
				PlanTailInsert(&message, "Server:Linux Web server\r\n");
				PlanTailInsert(&message, "Content-Type:text/html\r\n");
				
				PlanTailInsert(&content, "<html>\r\n");
				sprintf(lbuf, "<title>Directory listing for /%s%s</title>\r\n", file_path, file_name);
				PlanTailInsert(&content, lbuf);
				PlanTailInsert(&content, "<body><style> td {text-align:center}</style>");
				PlanTailInsert(&content, "<form method = \"POST\" accept-charset = \"GBK\">\r\n");
				sprintf(lbuf, "Hello %s!&nbsp&nbsp", id->us_name);
				PlanTailInsert(&content, lbuf);
				PlanTailInsert(&content, "<input type = \"hidden\" name = \"form_type\" value = \"out\">\r\n");
				PlanTailInsert(&content, "<input type = \"submit\" value = \"Logout\"></form></h4>\r\n");
				sprintf(lbuf, "<hr><fieldset><legend><h2>Directory listing for /%s%s</h2></legend>\r\n", file_path, file_name);
				PlanTailInsert(&content, lbuf);
				PlanTailInsert(&content, "<table rules=rows frame = hsides><tbody>\r\n");
				PlanTailInsert(&content, "<tr><th width = \"30%%\">FILE&nbsp&nbspNAME</th><th width = \"20%%\">SIZE</th><th width=\"20%%\">TIME</th><th width = \"15%%\">DOWNLOAD</th><th>DELETE</th></tr>\r\n");

				if(*file_name)
				{
					PlanTailInsert(&dir, "<tr>"
						"<td><a href=\"../\">../</a></td>"
						"<td></td>"
						"<td></td>"
						"<td></td>"
						"<td></td>"
					"</tr>\r\n");
				}
				struct dirent *dp;
				struct stat fstat;
				while((dp = readdir(dirp)) != NULL)
				{
					char fsize[BUF_SIZE];
					if(dp->d_name[0] == '.')
						continue;
					sprintf(lbuf, "%s/%s", UsURL, dp->d_name);
					if(stat(lbuf, &fstat) >= 0)
					{
						strcpy(buf, dp->d_name);
						
						sem_wait(&Sem_ctime);
						if(dp->d_type == DT_DIR)
						{
							strcat(buf, "/");
							sprintf(lbuf, "<tr>"
								"<td><a href=\"%s\">%s</a></td>"
								"<td></td>"
								"<td>%s</td>"
								"<td></td>"
								"<td><form method = \"POST\" accept-charset = \"GBK\">"
								"<input type = \"hidden\" name = \"form_type\" value = \"rm\">"
								"<input type = \"hidden\" name = \"file_name\" value = \"%s\">"
								"<input type = \"submit\" value = \"DELETE\"></form></td>"
							"</td>\r\n", buf, buf, ctime(&fstat.st_mtime), buf);
							PlanTailInsert(&dir, lbuf);
						}
						else
						{
							file_size = fstat.st_size;
							if(file_size > 10 * 1024)
							{
								file_size /= 1024;
								if(file_size > 10 * 1024)
								{
									file_size /= 1024;
									sprintf(fsize, "%dMB", file_size);
								}
								else
									sprintf(fsize, "%dKB", file_size);
							}
							else
								sprintf(fsize, "%dB", file_size);

							sprintf(lbuf, "<tr>"
								"<td><a href=\"%s\">%s</a></td>"
								"<td>%s</td>"
								"<td>%s</td>"
								"<td><a href = \"%s\" download = \"%s\">download</a></td>"
								
								"<td><form method = \"POST\" accept-charset = \"GBK\">"
								"<input type = \"hidden\" name = \"form_type\" value = \"rm\">"
								"<input type = \"hidden\" name = \"file_name\" value = \"%s\">"
								"<input type = \"submit\" value = \"DELETE\"></form></td>"
								
							"</tr>\r\n", buf, buf, fsize, ctime(&fstat.st_mtime), buf, buf, buf);
							PlanTailInsert(&file, lbuf);
						}
						sem_post(&Sem_ctime);
					}
					// PlanTailInsert(&content, lbuf);
				}

				PlanLink(&content, &dir);
				PlanLink(&content, &file);
				PlanTailInsert(&content, "</table></fieldset><hr>\r\n");

				PlanTailInsert(&content, "<form method = \"POST\" accept-charset = \"GBK\" autocomplete = \"off\" enctype = \"multipart/form-data\">\r\n");
				PlanTailInsert(&content, "<fieldset><legend>File Upload</legend>");
				PlanTailInsert(&content, "<input type = \"file\" name = \"file upload\"><input type = \"submit\" value = \"Upload\"></form></fieldset><hr>\r\n");
				
				PlanTailInsert(&content, "<form method = \"POST\" accept-charset = \"GBK\" autocomplete = \"off\">\r\n");
				PlanTailInsert(&content, "<fieldset><legend>Create Folder</legend>");
				PlanTailInsert(&content, "<input type = \"hidden\" name = \"form_type\" value = \"md\">\r\n");
				PlanTailInsert(&content, "folder&nbspname:<br><input type = \"text\" name = \"file_name\" value maxlength = \"50\">\r\n");
				PlanTailInsert(&content, "<input type = \"submit\" value = \"Create\"></form></fieldset>\r\n");
				
				PlanTailInsert(&content, "</body>\r\n</html>\r\n");
				
				int plansize;
				PlanSize(&content, &plansize, NULL);
				sprintf(lbuf, "Content-Length:%d\r\n", plansize);
				PlanIndexInsert(&message, lbuf, 4);

				closedir(dirp);
				PlanDestroy(&file);
				PlanDestroy(&dir);
			}

		}
		else // open requested file successfully
		{
			if((file = fopen(UsURL, "r")) == NULL)
			{
				result = 404;
				PlanCreate(&content);
				plangenerator(&message, &content, "404 Not Found", file_path, "");
			}
			else
			{
				// get file's size
				filefd = fileno(file);
				file_size = get_file_size(UsURL);
				if(file_size == -1)
				{
					result = 500;
					PlanCreate(&content);
					plangenerator(&message, &content, "500 Internal Server Error", file_path, "Server ERROR");
				}
				else
				{
					if((filep = (char*)mmap(0, file_size, PROT_READ, MAP_PRIVATE, filefd, 0)) == NULL)
					{
						result = 500;
						PlanCreate(&content);
						plangenerator(&message, &content, "500 Internal Server Error", file_path, "Server ERROR");
					}
					else
					{
						result = 200;
						PlanTailInsert(&message, "HTTP/1.1 200 OK\r\n");
						PlanTailInsert(&message, "Server:Linux Web server\r\n");

						sem_wait(&Sem_fill_file_type);
						sprintf(lbuf, "Content-Type:%s\r\n", fill_file_type(file_name, NULL));
						sem_post(&Sem_fill_file_type);

						PlanTailInsert(&message, lbuf);
						sprintf(lbuf, "Content-Length:%d\r\n", file_size);
						PlanTailInsert(&message, lbuf);
						if(download_flag)
							PlanTailInsert(&message, "Content-Disposition:attachment\r\n");
					}
				}
				fclose(file);
			}
		}
	}
	else
	{
		result = 404;
		PlanCreate(&content);
		plangenerator(&message, &content, "404 Not Found", file_path, "");
	}
	// send http message
	if(cookie_msg && *cookie_msg)
		PlanTailInsert(&message, cookie_msg);

	send_message_plan(fd, message, NULL);
	PlanDestroy(&message);
	rio_writen(fd, "\r\n", 2);
	if(filep)
	{
		send_message_buf(fd, filep, file_size);
		munmap(filep, file_size);
	}
	else if(PlanCheck(&content))
	{
		send_message_plan(fd, content, NULL);
		PlanDestroy(&content);
	}
	return result;
}
int request_POST(int fd, rio_t *riofd, char *URL, char *boundary, size_t content_length, Identity *id)
{
	char file_path[BUF_SIZE], file_name[BUF_SIZE];
	char lbuf[LONG_BUF_SIZE], *p, *tmp;
	char Uspath[LONG_BUF_SIZE], UsURL[LONG_BUF_SIZE];
	char Usboundary[BUF_SIZE];
	sprintf(Usboundary, "--%s--", boundary);

	if(file_path_split(URL, file_path, file_name) == 1) // corrected URL
	{
		strcat(file_path, file_name);
		sprintf(Uspath, "%s%s", id->us_root_path, file_path);
		*file_name = '\0';
		while(content_length)
		{
			int rs = rio_readlineb(riofd, lbuf, (content_length > BUF_SIZE ? LONG_BUF_SIZE : content_length));
			tail_delete(lbuf);
			content_length -= rs;
			if(!*lbuf)
				break;
			p = lbuf;
			while(p < lbuf + strlen(lbuf) - 10)
			{
				if(!memcmp(p, "filename=\"", 10))
				{
					p += 10;
					tmp = p;
					while(*tmp != '\"')
						tmp ++;
					memcpy(file_name, p, tmp - p);
					file_name[tmp - p] = '\0';
					break;
				}
				p++;
			}
		}

		sprintf(UsURL, "%s%s", Uspath, file_name);
		FILE *file = fopen(UsURL, "w");
		if(!file)
		{
			header_sender(fd, "403 Forbidden", file_path, "Illegal path");
			return 403;
		}
		else
		{
			while(content_length)
			{
				int rs = rio_readlineb(riofd, lbuf, (LONG_BUF_SIZE > content_length ? content_length : LONG_BUF_SIZE));
				content_length -= rs;
				if(!memcmp(lbuf, Usboundary, strlen(Usboundary)))
					break;
				fwrite(lbuf, rs, 1, file);
			}
			// header_sender(fd, "202 Accept", file_path, "File Upload Successfully");
			fclose(file);
			return 202;
		}
	}
	else
	{
		header_sender(fd, "403 Forbidden", file_path, "Illegal path");
		return 403;
	}
	return 202;
}
int request_LOGIN(int fd)
{
	char lbuf[LONG_BUF_SIZE], symbol;
	int size, pa, pb, ans;
	do{
		pa = rand() % 99 + 1;
		pb = rand() % 99 + 1;

		switch(rand() % 3)
		{
			case 0:
				symbol = '+';
				ans = pa + pb;
				break;
			case 1:
				symbol = '-';
				ans = pa - pb;
				break;
			case 2:
				symbol = '*';
				ans = pa * pb;
				break;
		}
	}while(ans >= 1000);

	Plan message, content;
	PlanCreate(&message);
	PlanCreate(&content);

	PlanTailInsert(&content, "<html><title>Server Login</title><body>\r\n");
	PlanTailInsert(&content, "<form method = \"POST\" accept-charset = \"GBK\" autocomplete = \"off\">\r\n");
	PlanTailInsert(&content, "<fieldset><legend>Server Login:</legend>user name:<br>\r\n");
	PlanTailInsert(&content, "<input type = \"hidden\" name = \"form_type\" value = \"01\">\r\n");
	PlanTailInsert(&content, "<input type = \"text\" name = \"us_name\"><br>password:<br><input type = \"password\" name = \"us_password\">\r\n");
	PlanTailInsert(&content, "<br>verification code:<br>\r\n");
	
	sprintf(lbuf, "<input type = \"text\" size = \"9\" value = \"%d%c%d=\" disabled>\r\n", pa, symbol, pb);
	// PlanTailInsert(&connent, "<input type = \"text\" size = \"9\" value = \"1+1=\" disabled>\r\n");
	PlanTailInsert(&content, lbuf);
	sprintf(lbuf, "<input type = \"hidden\" name = \"v_value\" value = \"%d\">\r\n", ans);
	PlanTailInsert(&content, lbuf);

	PlanTailInsert(&content, "<input type = \"text\" size = \"5\" name = \"verification\" value maxlength = \"6\"><br><br>\r\n");
	PlanTailInsert(&content, "<input type = \"submit\" value=\"Login\"></form>\r\n");
	
	PlanTailInsert(&content, "<br><br>");
	PlanTailInsert(&content, "<form method = \"POST\" accept-charset = \"GBK\" autocomplete = \"off\">\r\n");
	PlanTailInsert(&content, "<input type = \"hidden\" name = \"form_type\" value = \"01\">\r\n");
	PlanTailInsert(&content, "<input type = \"hidden\" name = \"us_name\" value = \"anonym\"><input type = \"hidden\" name = \"us_password\" value = \"111111\">\r\n");
	PlanTailInsert(&content, "<input type = \"submit\" value=\"Anonym Login\"></form>\r\n");

	PlanTailInsert(&content, "</fieldset></body></html>\r\n");

	PlanSize(&content, &size, NULL);

	PlanTailInsert(&message, "HTTP/1.1 200 OK");
	PlanTailInsert(&message, "Server:Linux Server\r\n");
	PlanTailInsert(&message, "Content-Type:text/html\r\n");
	sprintf(lbuf, "Content-Length:%d\r\n", size);
	PlanTailInsert(&message, lbuf);

	send_message_plan(fd, message, NULL);
	send_message_buf(fd, "\r\n", 2);
	send_message_plan(fd, content, NULL);

	PlanDestroy(&message);
	PlanDestroy(&content);

	return 401;
}

int request_REMOVE(char *URL, Identity *id)
{
	char UsURL[LONG_BUF_SIZE];
	sprintf(UsURL, "%s%s", id->us_root_path, URL);
	if(!remove(UsURL))
	{
		return 202;
	}
	else
	{
		return 400;
	}
}

int request_MKDIR(char *URL, Identity *id)
{
	char UsURL[LONG_BUF_SIZE];
	sprintf(UsURL, "%s%s", id->us_root_path, URL);
	if(mkdir(UsURL, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH) >= 0)
	{
		return 202;
	}
	else
	{
		return 400;
	}
}
/*****************************/
/*
* tools
*/
void fill_header_line(Header_Line *hl, char *buf)
{
	char *p = buf;
	while(*p && *p != ' ')
		p ++;
	memcpy(hl->head, buf, p - buf);
	hl->head[p - buf] = '\0';
	if(strlen(buf) <= p - buf)
		hl->content[0] = '\0';
	else
		strcpy(hl->content, p + 1);
	return;
}
int file_path_split(char *buf, char *file_path, char *file_name)
{
	static sem_t Sem;
	static unsigned char flag = 0;
	if(!flag)
	{
		flag = 1;
		sem_init(&Sem, 0, 1);
	}

	int STAT = 1;
	if(!strcmp(buf, "/"))
	{
		if(file_path)
			*file_path = '\0';
		if(file_name)
			*file_name = '\0';
		return 1;
	}
	Plan plan;
	PlanCreate(&plan);
	char str[BUF_SIZE], *s, *p, fbuf[LONG_BUF_SIZE];
	char *tail = &buf[strlen(buf)];

	sem_wait(&Sem);
	s = buf;
	p = buf;
	while(p <= tail)
	{
		if(*p == '/')
			break;
		p ++;
	}
	memcpy(str, s, p - s);
	str[p - s] = '\0';

	while(s < tail)
	{
		// string_decode(str);
		s < tail;
		if(!*str)
		{
		}
		else
		{
			if(strcmp(str, "."))
			{
				if(!strcmp(str, "..") )
				{
					if(PlanTailPop(&plan, NULL) == ERROR)
					{
						STAT = ILLEGAL;
						break;
					}
				}
				else
					PlanTailInsert(&plan, str);
			}
		}
		p ++;
		s = p;
		while(p <= tail)
		{
			if(*p == '/')
				break;
			p ++;
		}
		memcpy(str, s, p - s);
		str[p - s] = '\0';
	}
	sem_post(&Sem);

	if(STAT > 0)
	{
		if(file_name)
		{
			if(PlanTailPop(&plan, file_name) <= 0)
				file_name = '\0';
			if(*(tail - 1) == '/')
				strcat(file_name, "/");
		}
		if(file_path)
		{
			*file_path = '\0';
			while(PlanHeadPop(&plan, fbuf) > 0 && *fbuf)
			{	
				strcat(file_path, fbuf);
				strcat(file_path, "/");
			}
		}
	}
	PlanDestroy(&plan);
	return STAT;
}
char *fill_file_type(char *file, char *type)
{
	static char str[BUF_SIZE];
	char *strp = type ? type : str;
	*strp = '\0';
	char *p = &file[strlen(file) - 1];
	while(*p != '.' && p != file)
		p --;
	if(p == file)
	{
		strcpy(strp, "application/octet-stream");
	}
	else if(!strcmp(p, ".html") || !strcmp(p, ".htm"))
	{
		strcpy(strp, "text/html");
	}
	else if(!strcmp(p, ".dia"))
	{
		strcpy(strp, "text/plain");
	}
	else
	{
		FILE *chart = fopen("chart.txt", "r");
		if(!chart)
		{
			error_handle("in 'fill_file_type()': can't find file chart.txt");
			strcpy(strp, "application/octet-stream");
		}
		else
		{
			char cname[BUF_SIZE], ctype[BUF_SIZE];
			while(fscanf(chart, "%s", cname) != EOF && fscanf(chart, "%s", ctype) != EOF)
			{
				if(!strcmp(cname, p))
				{
					strcpy(strp, ctype);
					break;
				}
			}
			fclose(chart);
		}
	}
	if(!*strp)
		strcpy(strp, "text/plain");
	return strp;
}
int fill_cookie_jar(char *buf, Cookie_jar *cookie_jar)
{
	Cookie_jar *cj;
	char *s = buf, *p, *tail = buf + strlen(buf);
	while(s < tail)
	{
		while(s < tail)
		{
			if(*s >= 'a' && *s <= 'z' || *s >= 'A' && *s <= 'Z')
				break;
			s ++;
		}
		p = s + 1;
		while(p < tail && *p != ' ' && *p != '=')
			p ++;
		cj = (Cookie_jar*)malloc(sizeof(Cookie_jar));
		if(!cj)
			return ERROR;
		cj->cookie.name = (char *)malloc(p - s + 1);
		if(!cj->cookie.name)
			return ERROR;
		memcpy(cj->cookie.name, s, p - s);
		cj->cookie.name[p - s] = '\0';
		s = p + 1;
		while(s < tail)
		{
			if(*s >= 'a' && *s <= 'z' || *s >= 'A' && *s <= 'Z')
				break;
			s ++;
		}
		p = s + 1;
		while(p < tail && *p != ' ' && *p != ';')
			p ++;
		cj->cookie.value = (char *)malloc(p - s + 1);
		if(!cj->cookie.value)
			return ERROR;
		memcpy(cj->cookie.value, s, p - s);
		cj->cookie.value[p - s] = '\0';
		s = p + 1;
		cj->next = cookie_jar->next;
		cookie_jar->next = cj;
	}
	return 1;
}
int identify(Cookie_jar *cj, Identity **id)
{
	sem_wait(&Sem_ID_list);
	Identity *idp = ID_list.next;
	Cookie_jar *tmp;
	*id = NULL;
	while(idp)
	{
		tmp = cj->next;
		while(tmp)
		{
			if(!strcmp(tmp->cookie.name, "identity") && !strcmp(idp->identity, tmp->cookie.value))
			{
				*id = idp;
				time(&idp->last_time);
				sem_post(&Sem_ID_list);
				return 1;
			}
			tmp = tmp->next;
		}
		idp = idp->next;
	}
	sem_post(&Sem_ID_list);
	return 0;
}

int get_login_details(char *buf, char *us_name, char *us_password)
{
	char verification[BUF_SIZE];
	char *p = strtok(buf, "=");
	if(!p || strcmp(p, "us_name"))
		return ERROR;
	p = strtok(NULL, "&");
	if(!p)
		return ERROR;
	strcpy(us_name, p);
	p = strtok(NULL, "=");
	if(!p || strcmp(p, "us_password"))
		return ERROR;
	p = strtok(NULL, "&");
	if(!p)
		return ERROR;
	strcpy(us_password, p);

	if(!strcmp(us_name, "anonym"))
		return 1;

	p = strtok(NULL, "=");
	if(!p || strcmp(p, "v_value"))
		return ERROR;
	p = strtok(NULL, "&");
	if(!p)
		return ERROR;
	strcpy(verification, p);
	p = strtok(NULL, "=");
	if(!p || strcmp(p, "verification"))
		return ERROR;
	p = strtok(NULL, "&");
	if(!p || strcmp(verification, p))
		return ERROR;
	return 1;
}
int login(char *us_name, char *password, char *IP, Identity **idp)
{
	char nam[BUF_SIZE] = {0}, pasw[BUF_SIZE] = {0}, rootp[BUF_SIZE] = {0};
	char buf[BUF_SIZE], Uspassword[BUF_SIZE];
	char cookie_value[BUF_SIZE];
	Identity *id;
	if(!us_name || !*us_name)
	{
		strcpy(buf, "us_list/anonym.txt");
		strcpy(Uspassword, "non");
	}
	else
	{
		sprintf(buf, "us_list/%s.txt", us_name);
		password_encode(password, Uspassword);
	}

	FILE *us_list = fopen(buf, "r");
	if(us_list)
	{
		fscanf(us_list, "%s", nam);
		fscanf(us_list, "%s", pasw);
		fscanf(us_list, "%s", rootp);
		fclose(us_list);

		if((!us_name || !*us_name || !strcmp(nam, us_name)) && !strcmp(pasw, Uspassword))
		{
			id = (Identity*)malloc(sizeof(Identity));
			if(!id)
			{
				error_handle("in 'sign_in()': fail to allocate memory to struct Identity");
				return OVERFLOW;
			}
			strcpy(id->us_name, us_name);
			strcpy(id->us_root_path, rootp);
			strcpy(id->us_IP, IP);
			while(1)
			{
				cookie_value_rand(cookie_value);
				sem_wait(&Sem_ID_list);
				Identity *i = ID_list.next;
				while(i)
				{
					if(!strcmp(i->identity, cookie_value))
						break;
					i = i->next;
				}
				sem_post(&Sem_ID_list);
				if(!i)
					break;
			}

			id->identity = (char*)malloc(strlen(cookie_value) + 1);
			strcpy(id->identity, cookie_value);

			sem_wait(&Sem_ID_list);
			id->next = ID_list.next;
			ID_list.next = id;
			sem_post(&Sem_ID_list);

			sem_wait(&Sem_get_time);
			sprintf(buf, "%s:%s(%s) login", get_time(NULL), us_name, IP);
			sem_post(&Sem_get_time);
			msg_line_output_fp(stdout, buf);

			*idp = id;

			return 1;
		}
	}
	return ERROR;
}
int logout(char *us_name)
{
	char buf[BUF_SIZE];
	sem_wait(&Sem_ID_list);
	Identity *ip = &ID_list;
	while(ip && ip->next)
	{
		if(!strcmp(us_name, ip->next->us_name))
		{
			sem_wait(&Sem_get_time);
			sprintf(buf, "%s:%s(%s) logout", get_time(NULL), ip->next->us_name, ip->next->us_IP);
			sem_post(&Sem_get_time);
			msg_line_output_fp(stdout, buf);

			Identity *tmp = ip->next->next;
			free(ip->next->identity);
			free(ip->next);
			ip->next = tmp;
		}
		ip = ip->next;
	}
	sem_post(&Sem_ID_list);
	return 1;
}
int password_encode(char *password, char *buf)
{
	while(*password)
	{
		if(*password >= 80)
			*(buf ++) = *password - 47;
		else
			*(buf ++) = *password + 47;
		password ++;
	}
	*(buf ++) = '\0';
	return 1;
}
int cookie_value_rand(char *buf)
{
	sprintf(buf, "id%d", rand() % 99000 + 1000);
	// printf("cookie rand = %s\n\n", buf);
	return 1;
}
int send_message_plan(int fd, Plan plan, char *addmsg)
{
	Plan *t = plan.next;
	while(t)
	{
		rio_writen(fd, t->buf, strlen(t->buf));
		if(addmsg)
			rio_writen(fd, addmsg, strlen(addmsg));
		t = t->next;
	}
	return 1;
}
int send_message_buf(int fd, char *buf, int size)
{
	while(size)
	{
		if(size > SEND_MSG_SIZE)
		{
			rio_writen(fd, buf, SEND_MSG_SIZE);
			buf += SEND_MSG_SIZE;
			size -= SEND_MSG_SIZE;
		}
		else
		{
			rio_writen(fd, buf, size);
			break;
		}
	}
	return 1;
}

/******************************/
/*
* Plan generator
*/
int header_sender(int fd, char *what, char *back_path, char *msg)
{
	Plan message, content;
	PlanCreate(&message);
	PlanCreate(&content);

	plangenerator(&message, &content, what, back_path, msg);

	send_message_plan(fd, message, NULL);
	send_message_buf(fd, "\r\n", 2);
	send_message_plan(fd, content, NULL);

	PlanDestroy(&message);
	PlanDestroy(&content);
	return 1;
}
int plangenerator(Plan *message, Plan *content, char *what, char *back_path, char *msg)
{
	while(*back_path == '/')
		back_path ++;
	if(!message || !content)
		return -1;
	if(PlanCheck(message) == ERROR)
		PlanCreate(message);
	if(PlanCheck(content) == ERROR)
		PlanCreate(content);

	char lbuf[LONG_BUF_SIZE];
	int size;
	PlanTailInsert(content, "<html>\r\n");
	sprintf(lbuf, "<title>%s</title>\r\n", what);
	PlanTailInsert(content, lbuf);
	sprintf(lbuf, "<body><h2>%s</h2><br>\r\n", what);
	PlanTailInsert(content, lbuf);
	if(msg && *msg)
	{
		sprintf(lbuf, "<h4>%s</h4><hr>\r\n", msg);
		PlanTailInsert(content, lbuf);
	}
	PlanTailInsert(content, "<a href = \"/\">Back to /</a>\r\n");
	if(back_path && *back_path)
	{
		sprintf(lbuf, "&nbsp&nbsp&nbsp&nbsp<a href = \"/%s\">Back to /%s</a>\r\n", back_path, back_path);
		PlanTailInsert(content, lbuf);
	}
	PlanTailInsert(content, "</body></html>\r\n");
	PlanSize(content, &size, NULL);

	sprintf(lbuf, "HTTP/1.1 %s\r\n", what);
	PlanTailInsert(message, lbuf);
	PlanTailInsert(message, "Server:Linux Server\r\n");
	PlanTailInsert(message, "Content-Type:text/html\r\n");
	sprintf(lbuf, "Content-Length:%d\r\n", size);
	PlanTailInsert(message, lbuf);

	return 1;
}