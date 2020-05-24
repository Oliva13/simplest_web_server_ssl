/*
 * Copyright (c) 2016 Cesanta Software Limited
 * All rights reserved
 */

//#if MG_ENABLE_SSL
/*
 * This example starts an SSL web server on https://localhost:8443/
 *
 * Please note that the certificate used is a self-signed one and will not be
 * recognised as valid. You should expect an SSL error and will need to
 * explicitly allow the browser to proceed.
 */
#include <poll.h>
#include <unistd.h>
#include <sys/inotify.h>
#include "mongoose.h"

int done = 1;

static const char *s_http_port = "8043";
static const char *s_ssl_cert = "/tvh/etc/config/ssl_cert.pem";
static const char *s_ssl_key = "/tvh/etc/config/ssl_key.pem";

static struct mg_serve_http_opts s_http_server_opts;

pthread_mutex_t mpd_fch_mtx = PTHREAD_MUTEX_INITIALIZER;

#define PREFIX_MDASH	"/tvh/mpgdsh/"

char file_mpd_stream0[128] = {0};
char file_mpd_stream1[128] = {0};

#define strstartswith(p, prefix)	(strncmp(p, prefix, strlen(prefix))? 0 : 1)
#define strendswith(p, suffix)		(strncmp(p+strlen(p)-strlen(suffix), suffix, strlen(suffix))? 0 : 1)

static inline int path_testfile(const char* filename)
{
	struct stat info;
	return (stat(filename, &info)==0 && (info.st_mode&S_IFREG)) ? 1 : 0;
}


char *get_mpd_file(int stream)
{
	if(!stream)
	{
		return (file_mpd_stream0[0] ? file_mpd_stream0 : NULL);
	}
	else
	{
		if(stream)
		{
			//LOGE("get stream 1 -  %s\n", file_mpd_stream1);
			return (file_mpd_stream1[0] ? file_mpd_stream1 : NULL);
		}
		else
		{
			//LOGE("get NULL1\n");
			return NULL;
		}
	}
	//LOGE("get NULL2\n");
	return NULL;
}

int put_mpd_file(char *name)
{
	int res = 0;

	res = strstartswith(name, "start0-");
	if(res)
	{
		//LOGE("put stream 0 -  %s\n", name);	
		snprintf(file_mpd_stream0, sizeof(file_mpd_stream0), "%s%s", PREFIX_MDASH, name);
		//sprintf(file_mpd_stream0, "users:%s", username);
	}
	else
	{
		res = strstartswith(name, "start1-");
		if(res)
		{
			//LOGE("put stream 1 %s\n", name);
			snprintf(file_mpd_stream1, sizeof(file_mpd_stream1), "%s%s", PREFIX_MDASH, name);
		}		
	}	
	return 0;
}


void ev_handler(struct mg_connection *nc, int ev, void *ev_data) 
{
  int  res = 0;
  char *path_file = NULL; 
  char name[512];
  switch (ev) 
  {
    case MG_EV_ACCEPT: 
    {
      char addr[32];
      mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr), MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
      printf("%p: Connection from %s\r\n", nc, addr);
      break;
    }
    case MG_EV_HTTP_REQUEST: 
    {
      struct http_message *hm = (struct http_message *) ev_data;

      //char addr[32];
      
      //mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr), MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
      printf("1.%p: 2.%.*s 3.%.*s\r\n", nc, (int) hm->method.len, hm->method.p, (int) hm->uri.len, hm->uri.p);

      //memset(name, 0, 512);      
      //memcpy(name, hm->uri.p);
      //if (mg_vcmp(&hm->uri, "/start") == 0 || (mg_vcmp(&hm->uri, "/") == 0) 
      //{  
        //mg_send(nc, upload_form, strlen(upload_form));
      //}

     //if (strendswith(hm->uri.p, ".mpd"))
	    //{
         
          res = mg_vcmp(&hm->uri, "/start.mpd");
	  	    if(!res)
		      {
			       printf("stream 0 !!!\n");
			       pthread_mutex_lock(&mpd_fch_mtx);		
			       path_file = get_mpd_file(0); //To do res check
			       if(path_file == NULL)
			       {
				        pthread_mutex_unlock(&mpd_fch_mtx);		
				        printf("Error 404\n");
				        mg_http_send_error(nc, 404, NULL);
			       }

			       pthread_mutex_unlock(&mpd_fch_mtx);
			       printf("http_send_mpd_name %s =======>\n", path_file);
			       //mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
					 s_http_server_opts.document_root = "/tvh/mpgdsh";
					 s_http_server_opts.hidden_file_pattern = "$*.mpd";
					 s_http_server_opts.custom_mime_types =".mpd=text/xml";
					 //mg_serve_http(nc, hm, s_http_server_opts);
	
	        }

/*
          else
		      {
			        res = strcmp(hm->uri.p, "start1.mpd");
			        if(!res)
			        {
				          //LOGE("stream 1 !!!\n");
				          pthread_mutex_lock(&mpd_fch_mtx);		
				          path_file = get_mpd_file(1); //To do res check
				          if(path_file == NULL)
				          {
					            pthread_mutex_unlock(&mpd_fch_mtx);		
                      printf("Error 404\n");
					            //return http_server_send(session, 404, "", 0, NULL, NULL);
				          }
				          pthread_mutex_unlock(&mpd_fch_mtx);		
			        }
              else
              {
                  printf("Error 404\n");
    			        //return http_server_send(session, 404, "", 0, NULL, NULL);              
              }
          }*/
        	//printf("http_send_mpd_name %s =======>\n", path_file);
		      //return http_send_mpd_name(session, path_file);
      //}
      //else
      //{
            //printf("Send seg ------> %s\n", hm->uri.p);
            /*char send_seg_name[256]; 
		        snprintf(send_seg_name, sizeof(send_seg_name), PREFIX_MDASH"%s", hm->uri.p);
		        if(path_testfile(send_seg_name))
		        {
          			printf("sendname - %s =================>\n", send_seg_name);
			          //return http_send_html_name(session, send_seg_name);
		        }
		        else
		        {
			          printf("sendname - 404 %s ============== \n", send_seg_name);
          			//return http_server_send(session, 404, "", 0, NULL, NULL);
		        } 
            */   
     //}
  
      mg_serve_http(nc, hm, s_http_server_opts);

      //mg_send_response_line(nc, 200, "Content-Type: text/html\r\n""Connection: close");
      //mg_printf(nc, "\r\n<h1>Hello, %s!</h1>\r\n""You asked for %.*s\r\n", addr, (int) hm->uri.len, hm->uri.p);
      //nc->flags |= MG_F_SEND_AND_CLOSE;
      //led_blue = !led_blue;
      break;
    }
    case MG_EV_CLOSE: {
      printf("%p: Connection closed\r\n", nc);
      break;
    }
  }
}

static void on_sigterm(int pd)
{
	done = 0;
}

void *mpd_fchecker(void* param)
{
	int fd, wd, nb, offset, bufsize;
    char *buf;
    int res = 0;
    struct inotify_event *ev;
	bufsize = getpagesize();
	buf = (char *)malloc(bufsize);
	fd = inotify_init();
	struct pollfd pfd = {fd, POLLIN, 0};
	
	wd = inotify_add_watch(fd, "/tvh/mpgdsh", IN_CLOSE_WRITE);
	if (wd == -1)
            printf("inotify_add_watch\n");
    
	while(done)
    {
        offset = 0;
        memset (buf, 0, bufsize);
		int res = poll(&pfd, 1, 10);
		if (res < 0)
		{
			printf("failed to poll inotify\n");
			break;
		}
		else if (res == 0)
		{
			usleep(500);
			continue;
		}
		
        nb = read(fd, buf, bufsize);
		if (nb == 0)
            printf("read() from inotify fd returned 0!\n");
            
        if (nb == -1)
            printf("read\n");
		
        while (offset < nb && done) 
        {
            ev = (struct inotify_event *)(buf + offset);
            if (ev->mask & IN_CLOSE_WRITE) 
            {
            	pthread_mutex_lock(&mpd_fch_mtx);
            	res = put_mpd_file(ev->name);
            	pthread_mutex_unlock(&mpd_fch_mtx);
            }
            offset += sizeof (struct inotify_event) + ev->len;
        }
    }	

//exit_pthread:	
	
	free(buf);
	printf("---- exit from while mpd_fchecker -----\n");
	pthread_exit(NULL);
}


int main(void) 
{
  struct mg_mgr mgr;
  struct mg_connection *nc;
  struct mg_bind_opts bind_opts;
  const char *err;
  unsigned int status = 0;

  static pthread_t mpd_thr_fcheck;
	signal(SIGINT, on_sigterm);

  mg_mgr_init(&mgr, NULL);
  memset(&bind_opts, 0, sizeof(bind_opts));

 // bind_opts.ssl_cert = s_ssl_cert;
 // bind_opts.ssl_key = s_ssl_key;
 // bind_opts.error_string = &err;
//  printf("Starting SSL server on port %s, cert from %s, key from %s\n", s_http_port, bind_opts.ssl_cert, bind_opts.ssl_key);

  mkdir(PREFIX_MDASH, 0666);
	
  memset(file_mpd_stream0, 0, sizeof(file_mpd_stream0));
 	memset(file_mpd_stream1, 0, sizeof(file_mpd_stream1));
		
	status = pthread_create(&mpd_thr_fcheck, NULL, mpd_fchecker, NULL);
	if(status)
	{
		printf("Error sender pthread0_create - 0x%x\n", status);
		goto error;
  }

    nc = mg_bind_opt(&mgr, s_http_port, ev_handler, bind_opts);
    if (nc == NULL)
     {
	      printf("Failed to create listener: %s\n", err);
              return 1;
     }
    
  // Set up HTTP server parameters
  mg_set_protocol_http_websocket(nc);

  s_http_server_opts.document_root = "/mnt/nfs";  // Serve current directory
  s_http_server_opts.enable_directory_listing = "yes";

  for (;;)
  {
    if(!done)
      break;
    mg_mgr_poll(&mgr, 1000);
  }

  mg_mgr_free(&mgr);

error:
  
  printf("-----------------------exit main ------------------------\n");
	return 0;
}

