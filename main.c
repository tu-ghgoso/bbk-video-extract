#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <iconv.h>

char fname[0x300];
int lrc_len;
int dat_len;
unsigned char header_buf[0x300];
int lrc_offs;
int dat_offs;
unsigned char title[0x20];
unsigned char run_len;
unsigned char run_pos;
int run_len_tot;
int run_len_idx;
const unsigned char *run_len_array;
extern const unsigned char run_len_array_blm[0x80];
extern const unsigned char run_len_array_bmd[0x80];
unsigned char xor_keys_array[0x20];
int xor_chars_idx;
const unsigned char *xor_chars_array;
extern const unsigned char xor_chars_array_blm[0x2000];
extern const unsigned char xor_chars_array_bmd[0x2000];

void rotateright(unsigned char *bytes){
   unsigned char lsb,cur_lsb;
   lsb=bytes[0]&1;
   bytes[0]>>=1;
   cur_lsb=bytes[1]&1;
   if(cur_lsb)
      bytes[0]|=0x80;
   bytes[1]>>=1;
   cur_lsb=bytes[2]&1;
   if(cur_lsb)
      bytes[1]|=0x80;
   bytes[2]>>=1;
   cur_lsb=bytes[3]&1;
   if(cur_lsb)
      bytes[2]|=0x80;
   bytes[3]>>=1;
   if(lsb)
      bytes[3]|=0x80;
}

int read_header(FILE *f){
   int read=fread(header_buf,1,0x300,f);
   int i,j;
   char c;
   char blm[0x10]={0x45,0x45,0x42,0x42,0x4B,0x42,0x4C,0x4D,0x88,0x95,0xA8,0xB1,0x00,0x00,0x00,0x01};
   char bmd[0x10]={0x45,0x45,0x42,0x42,0x4B,0x42,0x4D,0x44,0x20,0x04,0x04,0x26,0x00,0x00,0x00,0x01};
   if(strncmp(header_buf,blm,0x10)==0){
      run_len_array=run_len_array_blm;
      xor_chars_array=xor_chars_array_blm;
      lrc_offs=0x40;
      fprintf(stderr,"INFO: Type BLM.\n");
   }
   else if(strncmp(header_buf,bmd,0x10)==0){
      run_len_array=run_len_array_bmd;
      xor_chars_array=xor_chars_array_bmd;
      lrc_offs=0x220;
      fprintf(stderr,"INFO: Type BMD.\n");
   }
   else{
      fprintf(stderr,"ERR: Wrong file tag!\n");
      return 0;
   }
   strncpy(title,header_buf+0x18,0x20);
   lrc_len=header_buf[0x10]+(header_buf[0x11]<<8)+(header_buf[0x12]<<16)+(header_buf[0x13]<<24);
   dat_len=header_buf[0x14]+(header_buf[0x15]<<8)+(header_buf[0x16]<<16)+(header_buf[0x17]<<24);
   dat_offs=lrc_len+lrc_offs;
   fprintf(stderr,"INFO: LRC len: %d; DAT len: %d.\n",lrc_len,dat_len);
   i=0;
   while(i<8){
      c=title[i*2+1];
      title[i*2+1]=title[i*2+17];
      title[i*2+17]=c;
      i++;
   }
   unsigned char title_keys[4];
   memcpy(title_keys,header_buf+0x14,4);
   title_keys[2]^=header_buf[0x11];
   title_keys[3]^=header_buf[0x10];
   rotateright(title_keys);
   rotateright(title_keys);
   rotateright(title_keys);
   i=0;
   j=0;
   while(i<0x20){
      title[i]^=title_keys[j];
      j=(j+1)%4;
      i++;
   }
   return 1;
}

void next_run(){
   xor_chars_idx=(xor_chars_idx+1)%0x2000;
   char c=xor_chars_array[xor_chars_idx];
   int i=0;
   while(i<0x20){
      xor_keys_array[i]=title[i]^c;
      i++;
   }
   run_len_idx=(run_len_idx+1)%0x80;
   run_len=run_len_array[run_len_idx];
   run_pos=0;
}

void show_status(long cur,long tot){
   static int pre_pos=0;
   static char line[]="\r     [>                             ]";
   int pos=(cur+1)*30/tot;
   if(pos!=pre_pos){
      line[pos+6]='=';
      if(pos<30){
	 line[pos+7]='>';
      }
      fprintf(stderr,"%s",line);
      pre_pos=pos;
      if(pos==30){
	 int i=1;
	 line[i+6]='>';
	 for(i=2;i<=30;i++){
	    line[i+6]=' ';
	 }
	 pre_pos=0;
      }
   }
}

void decode_str(char *str,int len){
   int i=0;
   while(i<len){
      show_status(i,len);
      str[i]^=xor_keys_array[run_pos];
      run_pos+=1;
      if(run_pos>=run_len){
	 next_run();
      }
      i++;
   }
   fprintf(stderr,"\n");
}

void init_keys(int offs){
   int i,ii;
   int offs_rr;
   int cur_run_len;
   char c;
   offs-=lrc_offs;
   run_len_tot=0;
   i=0;
   while(i<128){
      run_len_tot+=run_len_array[i];
      i++;
   }
   offs_rr=offs%run_len_tot;
   cur_run_len=0;
   i=0;
   while(i<128){
      cur_run_len+=run_len_array[i];
      if(cur_run_len>offs_rr){
	 run_len_idx=i;
	 run_len=run_len_array[run_len_idx];
	 run_pos=offs_rr+run_len-cur_run_len;
	 break;
      }
      i++;
   }
   xor_chars_idx=(run_len_idx+offs/run_len_tot*128)%0x2000;
   c=xor_chars_array[xor_chars_idx];
   i=0;
   while(i<0x20){
      xor_keys_array[i]=title[i]^c;
      i++;
   }
}

int main(int argc,char *argv[]){
   strcpy(fname,argv[1]);
   FILE *f=fopen(fname,"rb");
   if(read_header(f)){
      char ofname[0x400];
      strcpy(ofname,fname);
      char *ibuf;
      char *obuf;
      ibuf=header_buf+(lrc_offs-9);
      while(*ibuf==' '){
	 ibuf--;
      }
      *(ibuf+1)=0;
      size_t ol=0x200,il=(ibuf-(char *)header_buf)-0x16;
      if(il==lrc_offs-0x1F){
	 obuf=strrchr(ofname,'.');
	 char *p=obuf-1;
	 obuf+=5;
	 *obuf=0;
	 while(*p!='/'){
	    *(p+5)=*p;
	    p--;
	 }
	 p[1]='d';
	 p[2]='o';
	 p[3]='n';
	 p[4]='e';
	 p[5]='-';
	 
      }
      else{
	 ibuf=header_buf+0x18;
	 obuf=strrchr(ofname,'/');
	 strcpy(obuf,"/done-");
	 obuf+=6;
	 iconv_t cd=iconv_open("UTF-8","GBK");
	 iconv(cd,&ibuf,&il,&obuf,&ol);
	 iconv_close(cd);
	 obuf--;
      }
      fprintf(stderr,"INFO: %s\n",ofname);
      if(lrc_len){
	 char *lrc_str=malloc(lrc_len+0x100);
	 memset(lrc_str,0,lrc_len+0x100);
	 fseek(f,lrc_offs,SEEK_SET);
	 fread(lrc_str,1,lrc_len,f);
	 init_keys(lrc_offs);
	 decode_str(lrc_str,lrc_len);
	 strcpy(obuf,".LRC");
	 FILE *ff=fopen(ofname,"w+");
	 fwrite(lrc_str,1,lrc_len,ff);
	 fclose(ff);
	 free(lrc_str);
      }
      if(dat_len){
	 unsigned char *dat_str=malloc(dat_len+0x100);
	 memset(dat_str,0,dat_len+0x100);
	 fseek(f,dat_offs,SEEK_SET);
	 int read=fread(dat_str,1,dat_len,f);
	 init_keys(dat_offs);
	 decode_str(dat_str,dat_len);
	 int type_known=1;
	 if(strncmp(dat_str,"RIFF",4)==0&&strncmp(dat_str+8,"AVI LIST",8)==0){
	    strcpy(obuf,".AVI");
	 }
	 else if(strncmp(dat_str,"FWS",3)==0){
	    strcpy(obuf,".SWF");
	 }
	 else if(dat_str[0]==0xFF&&(dat_str[1]&0xE0)==0xE0){
	    strcpy(obuf,".MP3");
	 }
	 else{
	    int i;
	    fprintf(stderr,"ERR: Unknown header:");
	    for(i=0;i<10;i++){
	       fprintf(stderr," %02X",dat_str[i]);
	    }
	    fprintf(stderr,"\n");
	    strcpy(obuf,".DAT");
	    type_known=0;
	 }
	 if(type_known){
	    FILE *ff=fopen(ofname,"w+");
	    fwrite(dat_str,1,dat_len,ff);
	    fclose(ff);
	 }
	 else{
	    FILE *ff=fopen(ofname,"w+");
	    fwrite(dat_str,1,dat_len,ff);
	    fclose(ff);
	 }
	 free(dat_str);
      }
   }
   fclose(f);
}
