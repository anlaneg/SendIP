/* sendip.c - main program code for sendip
 * Copyright 2001 Mike Ricketts <mike@earth.li>
 * Distributed under the GPL.  See LICENSE.
 * Bug reports, patches, comments etc to mike@earth.li
 * ChangeLog since 2.0 release:
 * 27/11/2001 compact_string() moved to compact.c
 * 27/11/2001 change search path for libs to include <foo>.so
 * 23/01/2002 make random fields more random (Bryan Croft <bryan@gurulabs.com>)
 * 10/08/2002 detect attempt to use multiple -d and -f options
 * ChangeLog since 2.2 release:
 * 24/11/2002 compile on archs requiring alignment
 * ChangeLog since 2.3 release:
 * 21/04/2003 random data (Anand (Andy) Rao <andyrao@nortelnetworks.com>)
 * ChangeLog since 2.4 release:
 * 21/04/2003 fix errors detected by valgrind
 * 28/07/2003 fix compile error on solaris
 * ChangeLog since 2.5 release:
 * 10/04/2004 use setsockopt for ipv6 options.
 * 11/04/2004 allow setting socket options via -s
 */

#define _SENDIP_MAIN

/* socket stuff */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

/* everything else */
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <ctype.h> /* isprint */
#include "sendip_module.h"

#include "ipv4.h"
#include "ipv6.h"

/* Use our own getopt to ensure consistant behaviour on all platforms */
#include "gnugetopt.h"

typedef struct _s_m {
  struct _s_m *next;
  struct _s_m *prev;
  char *name;/*模块名称*/
  char optchar;
  sendip_data * (*initialize)(void);
  bool (*do_opt)(const char *optstring, const char *optarg, 
					  sendip_data *pack);
  bool (*set_addr)(char *hostname, sendip_data *pack);
  bool (*finalize)(char *hdrs, sendip_data *headers[], sendip_data *data, 
						 sendip_data *pack);
  sendip_data *pack;
  void *handle;
  sendip_option *opts;
  int num_opts;
} sendip_module;

/* sockaddr_storage struct is not defined everywhere, so here is our own
   nasty version
*/
typedef struct {
  u_int16_t ss_family;
  u_int32_t ss_align;
  char ss_padding[122];
} _sockaddr_storage;

static int num_opts=0;/*记录系统总选项数目*/
static sendip_module *first;
static sendip_module *last;

static char *progname;

/*报文发送*/
static int sendpacket(sendip_data *data, char *hostname, int af_type,
							 bool verbose, char *sockopts) {
  _sockaddr_storage *to = malloc(sizeof(_sockaddr_storage));
  int tolen;
  
  /* socket stuff */
  int s;                              /* socket for sending       */
  bool sethdrincl=(af_type==AF_INET); /* should we set IP_HDRINCL?*/
  bool setipv6opts=(af_type==AF_INET6);/* should we set IPV6_*?   */
  
  /* hostname stuff */
  struct hostent *host = NULL;      /* result of gethostbyname2 */
  
  /* casts for specific protocols */
  struct sockaddr_in *to4 = (struct sockaddr_in *)to; /* IPv4 */
  struct sockaddr_in6 *to6 = (struct sockaddr_in6 *)to; /* IPv6 */
  
  int sent;                         /* number of bytes sent */
  
  if(to==NULL) {
    perror("OUT OF MEMORY!\n");
    return -3;
  }
  memset(to, 0, sizeof(_sockaddr_storage));
  
  /*取对端地址*/
  if ((host = gethostbyname2(hostname, af_type)) == NULL) {
    perror("Couldn't get destination host: gethostbyname2()");
    free(to);
    return -1;
  }
  
  switch (af_type) {
  case AF_INET:
    to4->sin_family = host->h_addrtype;
    memcpy(&to4->sin_addr, host->h_addr, host->h_length);
    tolen = sizeof(struct sockaddr_in);
    break;
  case AF_INET6:
    to6->sin6_family = host->h_addrtype;
    memcpy(&to6->sin6_addr, host->h_addr, host->h_length);
    tolen = sizeof(struct sockaddr_in6);
    break;
  default:
    return -2;
    break;
  }
  
  /*显示报文内容*/
  if(verbose) { 
    int i, j;  
    printf("Final packet data:\n");
    for(i=0; i<data->alloc_len; ) {
      for(j=0; j<4 && i+j<data->alloc_len; j++)
		  printf("%02X ", ((unsigned char *)(data->data))[i+j]); 
      printf("  ");
      for(j=0; j<4 && i+j<data->alloc_len; j++) {
		  int c=(int) ((unsigned char *)(data->data))[i+j];
		  printf("%c", isprint(c)?((char *)(data->data))[i+j]:'.'); 
      }
      printf("\n");
      i+=j;
    }
  }
  
  /*打开af_inet/af_inet6 raw socket*/
  if ((s = socket(af_type, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("Couldn't open RAW socket");
    free(to);
    return -1;
  }
  
  /* Set socket options */
  if(verbose) printf("Setting socket options:\n");
  if(sockopts && strlen(sockopts)) {
	  /*用户要求了socket选项*/
    int i;
    const int on=1;
    for(i=0;i<strlen(sockopts);i++) {
      switch(sockopts[i]) {
      case 'b':
		  if(verbose) printf(" SO_BROADCAST\n");
		  if(setsockopt(s, SOL_SOCKET, SO_BROADCAST,(const void *)&on,sizeof(on))<0) {
			 perror("Couldn't setsockopt SO_BROADCAST");
			 free(to);
			 close(s);
			 return -2;
		  }
		  break;
      case 'i':
		  sethdrincl = FALSE;
		  break;
      case '6':
		  setipv6opts = FALSE;
		  break;
      default:
		  fprintf(stderr,"Socket option %c NOT UNDERSTOOD, valid ones are 'b' and 'i'\n",sockopts[i]);
		  fprintf(stderr,"Option will be ignored\n");
		  break;
      }
    }
  }
  
  /* Need this for OpenBSD, shouldn't cause problems elsewhere */
  if(sethdrincl) { 
    const int on=1;
    if(verbose) printf(" IP_HDRINCL\n");
    if (setsockopt(s, IPPROTO_IP,IP_HDRINCL,(const void *)&on,sizeof(on)) <0) { 
      perror ("Couldn't setsockopt IP_HDRINCL");
      free(to);
      close(s);
      return -2;
    }
  }
  
  /* Setting various IPV6 header option requires using setsockopt, as
     in RFCs 3493, 3542, 2292.
  */
  if(af_type == setipv6opts) {
    ipv6_header *iphdr = (ipv6_header *)data->data;
    if(verbose) printf(" IPV6_UNICAST_HOPS\n");
    if (setsockopt(s,IPPROTO_IPV6,IPV6_UNICAST_HOPS,
						 &(iphdr->ip6_hlim),sizeof(iphdr->ip6_hlim)) < 0) {
      perror("Couldnt set Sock options for IPv6:Hop Limit");
      free(to);
      close(s);
      return -2;
    }
  }
  
  
#ifdef __sun__
  /* On Solaris, it seems that the only way to send IP options or packets
     with a faked IP header length is to:
     setsockopt(IP_OPTIONS) with the IP option data and size
     decrease the total length of the packet accordingly
     I'm sure this *shouldn't* work.  But it does.
  */
  if((*((char *)(data->data))&0x0F) != 5) {
    ip_header *iphdr = (ip_header *)data->data;
    
    int optlen = iphdr->header_len*4-20;
    
    if(verbose) 
      printf("Solaris workaround enabled for %d IP option bytes\n", optlen);
    
    iphdr->tot_len = htons(ntohs(iphdr->tot_len)-optlen);
    
    if(verbose) printf(" IP_OPTIONS\n");
    if(setsockopt(s,IPPROTO_IP,IP_OPTIONS,
						(void *)(((char *)(data->data))+20),optlen)) {
      perror("Couldn't setsockopt IP_OPTIONS");
      free(to);
      close(s);
      return -2;
    }
  }
#endif /* __sun__ */
  
  /* Send the packet */
  /*向外发送*/
  sent = sendto(s, (char *)data->data, data->alloc_len, 0, (void *)to/*目的地址*/, tolen);
  if (sent == data->alloc_len) {
    if(verbose) printf("Sent %d bytes to %s\n",sent,hostname);
  } else {
    if (sent < 0) {
      perror("sendto");
    } else {
      if(verbose) fprintf(stderr, "Only sent %d of %d bytes to %s\n", 
								  sent, data->alloc_len, hostname);
    }
  }
  free(to);
  close(s);
  return sent;
}

static void unload_modules(bool freeit, int verbosity) {
  sendip_module *mod, *p;
  p = NULL;
  for(mod=first;mod!=NULL;mod=mod->next) {
    if(verbosity) printf("Freeing module %s\n",mod->name);
    if(p) free(p);
    p = mod;
    free(mod->name);
    if(freeit) free(mod->pack->data);
    free(mod->pack);
    (void)dlclose(mod->handle);
    /* Do not free options - TODO should we? */
  }
  if(p) free(p);
}

static bool load_module(char *modname) {
  sendip_module *newmod = malloc(sizeof(sendip_module));
  sendip_module *cur;
  int (*n_opts)(void);
  sendip_option * (*get_opts)(void);
  char (*get_optchar)(void);
  
  for(cur=first;cur!=NULL;cur=cur->next) {
    if(!strcmp(modname,cur->name)) {
      /*此模块已加载，退出,但此时需要添加newmod,它是cur的一个副本*/
      memcpy(newmod,cur,sizeof(sendip_module));
      newmod->num_opts=0;
      goto out;
    }
  }
  newmod->name=malloc(strlen(modname)+strlen(SENDIP_LIBS)+strlen(".so")+2);
  strcpy(newmod->name,modname);
  if(NULL==(newmod->handle=dlopen(newmod->name,RTLD_NOW))) {
    char *error0=strdup(dlerror());
    /*修改为当前路径，再尝试一次*/
    sprintf(newmod->name,"./%s.so",modname);
    if(NULL==(newmod->handle=dlopen(newmod->name,RTLD_NOW))) {
      char *error1=strdup(dlerror());
      /*修改到SENDIP_LIBS路径，再尝试一次*/
      sprintf(newmod->name,"%s/%s.so",SENDIP_LIBS,modname);
      if(NULL==(newmod->handle=dlopen(newmod->name,RTLD_NOW))) {
		  char *error2=strdup(dlerror());
		  /*modname中也许包含了.so后缀，尝试下*/
		  sprintf(newmod->name,"%s/%s",SENDIP_LIBS,modname);
		  if(NULL==(newmod->handle=dlopen(newmod->name,RTLD_NOW))) {
			 char *error3=strdup(dlerror());
			 fprintf(stderr,"Couldn't open module %s, tried:\n",modname);
			 fprintf(stderr,"  %s\n  %s\n  %s\n  %s\n", error0, error1,
						error2, error3);
			 free(newmod);
			 free(error3);
			 return FALSE;
		  }
		  free(error2);
      }
      free(error1);
    }
    free(error0);
  }

  /*modname路径及名称确认*/
  strcpy(newmod->name,modname);

  /*在so中查找initialize函数*/
  if(NULL==(newmod->initialize=dlsym(newmod->handle,"initialize"))) {
    fprintf(stderr,"%s doesn't have an initialize function: %s\n",modname,
				dlerror());
    dlclose(newmod->handle);
    free(newmod);
    return FALSE;
  }

  /*在so中查找do_opt函数*/
  if(NULL==(newmod->do_opt=dlsym(newmod->handle,"do_opt"))) {
    fprintf(stderr,"%s doesn't contain a do_opt function: %s\n",modname,
				dlerror());
    dlclose(newmod->handle);
    free(newmod);
    return FALSE;
  }

  /*在so中查找set_addr函数*/
  newmod->set_addr=dlsym(newmod->handle,"set_addr"); // don't care if fails
  if(NULL==(newmod->finalize=dlsym(newmod->handle,"finalize"))) {
    fprintf(stderr,"%s\n",dlerror());
    dlclose(newmod->handle);
    free(newmod);
    return FALSE;
  }

  /*在so中查找num_opts函数*/
  if(NULL==(n_opts=dlsym(newmod->handle,"num_opts"))) {
    fprintf(stderr,"%s\n",dlerror());
    dlclose(newmod->handle);
    free(newmod);
    return FALSE;
  }

  /*在so中查找get_opts函数*/
  if(NULL==(get_opts=dlsym(newmod->handle,"get_opts"))) {
    fprintf(stderr,"%s\n",dlerror());
    dlclose(newmod->handle);
    free(newmod);
    return FALSE;
  }

  /*在so中查找get_optchar函数*/
  if(NULL==(get_optchar=dlsym(newmod->handle,"get_optchar"))) {
    fprintf(stderr,"%s\n",dlerror());
    dlclose(newmod->handle);
    free(newmod);
    return FALSE;
  }

  /*触发so中的函数，获知选项数目，短选项，及选项结构体*/
  newmod->num_opts = n_opts();
  newmod->optchar=get_optchar();
  /* TODO: check uniqueness */
  newmod->opts = get_opts();
  
  /*系统总选项数组增多*/
  num_opts+=newmod->num_opts;
  
 out:
 /*将新加载的模块填串进first链表中*/
  newmod->pack=NULL;
  newmod->prev=last;
  newmod->next=NULL;
  last = newmod;
  if(last->prev) last->prev->next = last;
  if(!first) first=last;
  
  return TRUE;
}

static void print_usage(void) {
  sendip_module *mod;
  int i;
  printf("Usage: %s [-v] [-d data] [-h] [-f datafile] [-p module] [module options] hostname\n",progname);
  printf(" -d data\tadd this data as a string to the end of the packet\n");
  printf("\t\tData can be:\n");
  printf("\t\trN to generate N random(ish) data bytes;\n");
  printf("\t\t0x or 0X followed by hex digits;\n");
  printf("\t\t0 followed by octal digits;\n");
  printf("\t\tany other stream of bytes\n");
  printf(" -s options\tset socket options\n");
  printf("\t\tValid options are:\n");
  printf("\t\tb (SO_BROADCAST) allow sending packets to broadcast addresses;\n");
  printf("\t\ti (IP_HDRINCL) (ON BY DEFAULT) include IP headers (expert use only!);\n");
  printf("\t\t6 (IPV6_*) (ON BY DEFAULT) various options for setting ipv6 headers\n");
  printf(" -f datafile\tread packet data from file\n");
  printf(" -h\t\tprint this message\n");
  printf(" -p module\tload the specified module (see below)\n");
  printf(" -v\t\tbe verbose\n");
  
  printf("\n\nModules are loaded in the order the -p option appears.  The headers from\n");
  printf("each module are put immediately inside the headers from the previos model in\n");
  printf("the final packet.  For example, to embed bgp inside tcp inside ipv4, do\n");
  printf("sendip -p ipv4 -p tcp -p bgp ....\n");
  
  printf("\n\nModules available at compile time:\n");
  printf("\tipv4 ipv6 icmp tcp udp bgp rip ntp\n\n");
  for(mod=first;mod!=NULL;mod=mod->next) {
    printf("\n\nArguments for module %s:\n",mod->name);
    for(i=0;i<mod->num_opts;i++) {
      printf("   -%c%s %c\t%s\n",mod->optchar,
				 mod->opts[i].optname,mod->opts[i].arg?'x':' ',
				 mod->opts[i].description);
      if(mod->opts[i].def) printf("   \t\t  Default: %s\n", 
											 mod->opts[i].def);
    }
  }
  
}

int main(int argc, char *const argv[]) {
  int i;
  
  struct option *opts=NULL;
  int longindex=0;
  char rbuff[31];
  
  bool usage=FALSE, verbosity=FALSE;
  
  char *data=NULL;
  int datafile=-1;
  int datalen=0;
  bool randomflag=FALSE;
  
  char *sockopts=NULL;
  
  sendip_module *mod;
  int optc;
  
  int num_modules=0;/*加载的模块数目*/
  
  sendip_data packet;
  
  num_opts = 0;	
  first=last=NULL;
  
  progname=argv[0];
  
  /* magic random seed that gives 4 really random octets */
  srandom(time(NULL) ^ (getpid()+(42<<15)));
  
  /* First, get all the builtin options, and load the modules */
  gnuopterr=0; gnuoptind=0;
  while(gnuoptind<argc && (EOF != (optc=gnugetopt(argc,argv,"-p:vd:hf:s:")))) {
	 switch(optc) {
	 case 'p':
		 /*扫描-p选项，按顺序加载指定模块*/
		if(load_module(gnuoptarg))
		  num_modules++;
		break;
	 case 'v':
		verbosity=TRUE;
		break;
	 case 'd':
		if(data == NULL) {
		  data=gnuoptarg;
		  if(*data=='r') {
			  /*-d r<n> 选项，随机生成n个字节数据，将其做为data*/
			 /* random data, format is r<n> when n is number of bytes */
			 datalen = atoi(data+1);
			 if(datalen < 1) {
				fprintf(stderr,"Random data with length %d invalid\nNo data will be included\n",datalen);
				data=NULL;
				datalen=0;
			 }
			 data=(char *)malloc(datalen);
			 for(i=0;i<datalen;i++)
				data[i]=(char)random();
			 randomflag=TRUE;
		  } else {
			  /*普通的-d,指明：1。以0[xX]开头的16进制；2。以0开头的8进制；3。其它按字符串处理*/
			 /* "normal" data */
			 datalen = compact_string(data);
		  }
		} else {
		  fprintf(stderr,"Only one -d or -f option can be given\n");
		  usage = TRUE;
		}
		break;
	 case 'h':
		usage=TRUE;
		break;
	 case 'f':
		if(data == NULL) {
		  /*通过-f给定data file*/
		  datafile=open(gnuoptarg,O_RDONLY);
		  if(datafile == -1) {
			 perror("Couldn't open data file");
			 fprintf(stderr,"No data will be included\n");
		  } else {
			 datalen = lseek(datafile,0,SEEK_END);
			 if(datalen == -1) {
				perror("Error reading data file: lseek()");
				fprintf(stderr,"No data will be included\n");
				datalen=0;
			 } else if(datalen == 0) {
				fprintf(stderr,"Data file is empty\nNo data will be included\n");
			 } else {
				data = mmap(NULL,datalen,PROT_READ,MAP_SHARED,datafile,0);
				if(data == MAP_FAILED) {
				  perror("Couldn't read data file: mmap()");
				  fprintf(stderr,"No data will be included\n");
				  data = NULL;
				  datalen=0;
				}
			 }
		  }
		} else {
		  fprintf(stderr,"Only one -d or -f option can be given\n");
		  usage = TRUE;
		}
		break;
	 case 's':
		sockopts=strdup(gnuoptarg);
		if(sockopts==NULL) {
		  perror("Couldn't allocate memory for socket options");
		  usage = TRUE;
		}
		break;
	 case '?':
	 case ':':
		/* skip any further characters in this option
			this is so that -tonop doesn't cause a -p option
		*/
		nextchar = NULL; gnuoptind++;
		break;
	 }
  }
  
  /* Build the getopt listings */
  /*构造各模块引入的选项，将其合并到opts中*/
  opts = malloc((1+num_opts)*sizeof(struct option));
  if(opts==NULL) {
	 if(sockopts) free(sockopts);
	 perror("OUT OF MEMORY!\n");
	 return 1;
  }
  memset(opts,'\0',(1+num_opts)*sizeof(struct option));
  i=0;
  for(mod=first;mod!=NULL;mod=mod->next) {
	 int j;
	 char *s;   // nasty kludge because option.name is const
	 for(j=0;j<mod->num_opts;j++) {
		/* +2 on next line is one for the char, one for the trailing null */
		opts[i].name = s = malloc(strlen(mod->opts[j].optname)+2);
		sprintf(s,"%c%s",mod->optchar,mod->opts[j].optname);
		opts[i].has_arg = mod->opts[j].arg;
		opts[i].flag = NULL;
		opts[i].val = mod->optchar;
		i++;
	 }
  }
  if(verbosity) printf("Added %d options\n",num_opts);
  
  /* Initialize all */
  /*模块初始化，各模块生成自已的mod->pack*/
  for(mod=first;mod!=NULL;mod=mod->next) {
	 if(verbosity) printf("Initializing module %s\n",mod->name);
	 mod->pack=mod->initialize();
  }
  
  /* Do the get opt */
  gnuopterr=1;
  gnuoptind=0;
  while(EOF != (optc=getopt_long_only(argc,argv,"p:vd:hf:s:",opts,&longindex))) {
	 
	 switch(optc) {
	 case 'p':
	 case 'v':
	 case 'd':
	 case 'f':
	 case 's':
	 case 'h':
		/* Processed above */
		break;
	 case ':':
		usage=TRUE;
		fprintf(stderr,"Option %s requires an argument\n",
				  opts[longindex].name);
		break;
	 case '?':
		usage=TRUE;
		fprintf(stderr,"Option starting %c not recognized\n",gnuoptopt);
		break;
	 default:
		for(mod=first;mod!=NULL;mod=mod->next) {
		  if(mod->optchar==optc/*optc匹配*/) {
			 
			 /* Random option arguments */
			 /*为各模块设置的-r参数，用于生成随机值*/
			 if(gnuoptarg != NULL && !strcmp(gnuoptarg,"r")) {
				/* need a 32 bit number, but random() is signed and
					nonnegative so only 31bits - we simply repeat one */
				unsigned long r = (unsigned long)random()<<1;
				r+=(r&0x00000040)>>6;
				sprintf(rbuff,"%lu",r);
						gnuoptarg = rbuff;
			 }
			 
			 /*使模块具体处理选项，产生报文内容*/
			 if(!mod->do_opt(opts[longindex].name,gnuoptarg,mod->pack)) {
				usage=TRUE;
			 }
		  }
		}
	 }
  }
  
  /* gnuoptind is the first thing that is not an option - should have exactly
	  one hostname...
  */
  if(argc != gnuoptind+1) {
	 usage=TRUE;
	 if(argc-gnuoptind < 1) fprintf(stderr,"No hostname specified\n");
	 else fprintf(stderr,"More than one hostname specified\n");
  } else {
	  /*设置目标地址*/
	 if(first && first->set_addr) {
		first->set_addr(argv[gnuoptind],first->pack);
	 }
  }
  
  /* free opts now we have finished with it */
  for(i=0;i<(1+num_opts);i++) {
	 if(opts[i].name != NULL) free((void *)opts[i].name);
  }
  free(opts); /* don't need them any more */
  
  if(usage) {
	  /*显示用法*/
	 print_usage();
	 unload_modules(TRUE,verbosity);
	 if(datafile != -1) {
		munmap(data,datalen);
		close(datafile);
		datafile=-1;
	 }
	 if(randomflag) free(data);
	 if(sockopts) free(sockopts);
	 return 0;
  }
  
  
  /* EVIL EVIL EVIL! */
  /* Stick all the bits together.  This means that finalize better not
	  change the size or location of any packet's data... */
  packet.data = NULL;
  packet.alloc_len = 0;
  packet.modified = 0;
  /*获取各模块需要的报文总长度*/
  for(mod=first;mod!=NULL;mod=mod->next) {
	 packet.alloc_len+=mod->pack->alloc_len;
  }
  /*还需要包含用户指定的datalen*/
  if(data != NULL) packet.alloc_len+=datalen;
  packet.data = malloc(packet.alloc_len);

  /*各模块将报文内容填入*/
  for(i=0, mod=first;mod!=NULL;mod=mod->next) {
	 memcpy((char *)packet.data+i,mod->pack->data,mod->pack->alloc_len);
	 free(mod->pack->data);
	 mod->pack->data = (char *)packet.data+i;/*更改mod->pack使其指向最终内容*/
	 i+=mod->pack->alloc_len;
  }
  
  /* Add any data */
  /*将用户指定的数据内容填入*/
  if(data != NULL) memcpy((char *)packet.data+i,data,datalen);
  if(datafile != -1) {
	 munmap(data,datalen);
	 close(datafile);
	 datafile=-1;
  }
  if(randomflag) free(data);
  
  /* Finalize from inside out */
  {
	 char hdrs[num_modules];
	 sendip_data *headers[num_modules];
	 sendip_data d;
	 
	 d.alloc_len = datalen;
	 d.data = (char *)packet.data+packet.alloc_len-datalen;
	 
	 /*正序收集各header*/
	 for(i=0,mod=first;mod!=NULL;mod=mod->next,i++) {
		hdrs[i]=mod->optchar;
		headers[i]=mod->pack;
	 }
	 
	 /*反序调用finalize回调，*/
	 for(i=num_modules-1,mod=last;mod!=NULL;mod=mod->prev,i--) {
		
		if(verbosity) printf("Finalizing module %s\n",mod->name);
		
		/* Remove this header from enclosing list */
		hdrs[i]='\0';/*移除当前header的选项为'\0'*/
		headers[i] = NULL;/*移除当前header为NULL*/
		
		/*执行当前mod的finalize,此时headers自i向后均已清空*/
		mod->finalize(hdrs, headers, &d, mod->pack);
		
		/* Get everything ready for the next call */
		d.data=(char *)d.data-mod->pack->alloc_len;/*data指针前移*/
		d.alloc_len+=mod->pack->alloc_len;
	 }
  }
  
  /* And send the packet */
  {
	 int af_type;
	 if(first==NULL) {
		if(data == NULL) {
		  fprintf(stderr,"Nothing specified to send!\n");
		  print_usage();
		  free(packet.data);
		  unload_modules(FALSE,verbosity);
		  return 1;
		} else {
		  af_type = AF_INET;
		}
	 }
	 else if(first->optchar=='i') af_type = AF_INET; /*采用ipv4协议发包*/
	 else if(first->optchar=='6') af_type = AF_INET6;/*采用ipv6协议发包*/
	 else {
		fprintf(stderr,"Either IPv4 or IPv6 must be the outermost packet\n");
		unload_modules(FALSE,verbosity);
		free(packet.data);
		if(sockopts) free(sockopts);
		return 1;
	 }
	 i = sendpacket(&packet/*构造好的报文*/,argv[gnuoptind]/*目标地址*/,af_type,verbosity,sockopts);
	 free(packet.data);
	 free(sockopts);
  }
  unload_modules(FALSE,verbosity);
  return 0;
}
