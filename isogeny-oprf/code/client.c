#include <sys/types.h>  
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>

#include <stdbool.h>

#include "rng.h"
#include "csidh.h"
#include "network-utils.h"
#ifndef HASHLEN
#define HASHLEN 128
#endif


int main(int argc, char **argv){
  double overall=0;
  double start,end;
      struct timespec now;

  if(argc != 3){
    puts("usage: IP, port"); 
    return -1; 
  }
  //////////////////////////////////////////////
  /////////////////// Socket setup /////////////
  //////////////////////////////////////////////

  char* hostname=argv[1]; 
  size_t port=atoll(argv[2]); 
  if(port==0){
    puts("Port needs to be a nonzero integer. ");
    return -1;
  }
  else if(port>=(1<<16)){
    puts("Port needs to be an integer in the range 1--(1<<16-1)");
    return -1;
  }

  struct sockaddr_in s;
  memset((void*)&s, 0, sizeof(s));
  s.sin_family = AF_INET;
  s.sin_addr.s_addr = inet_addr(hostname);
  s.sin_port = htons(port);
  
  // Not from original implementation
  size_t nrIterations = 10;
  char output_text[2500];
  time_t rawtime;
  struct tm * timeinfo;
  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  sprintf(output_text, "OPUS benchmark from %s with n = %ld iterations:\n",asctime(timeinfo), nrIterations);
  //sprintf(output_text,"User input: %s\n",msg);
  sprintf(output_text+strlen(output_text),"-------------------------\n");
  sprintf(output_text+strlen(output_text),"Measured time for each run:\n");
  double time_stamp[nrIterations];
  // Again original
  
  for(size_t runs=0; runs<nrIterations; ++runs){
  int csocket = socket(AF_INET, SOCK_STREAM, 0);
  while (connect(csocket, (struct sockaddr *)&s,
        sizeof(struct sockaddr)) < 0);
  clock_gettime(CLOCK_REALTIME, &now);
  start= now.tv_sec + now.tv_nsec*1e-9;
  bool msg[HASHLEN];
  for(size_t i=0; i<HASHLEN; i++)
    msg[i]=(bool)(rand()%2);
    

  //////////////////////////////////////////////
  /////////////////// OPRF /////////////////////
  //////////////////////////////////////////////
  large_private_key unblind={0};
  public_key client_result={0}; 
  for(size_t i=0; i<HASHLEN; ++i){
    private_key blinder={0};
    csidh_private(&blinder);
    csidh(&client_result, &client_result, &blinder); 
    send(csocket, &client_result, sizeof(client_result),0);
    sub_large_key(&unblind, &blinder);
    Response response;
    recv(csocket, &response, sizeof(response),0);
    if(msg[i]){
      // unblind and update
      memcpy(&client_result, &response.E[1], sizeof(public_key));
    }
    else{
      memcpy(&client_result, &response.E[0], sizeof(public_key));
    }
  }
  private_key blinder={0};
  csidh_private(&blinder);
  csidh(&client_result, &client_result, &blinder); 
  send(csocket, &client_result, sizeof(client_result),0);
  sub_large_key(&unblind, &blinder);
  recv(csocket, &client_result, sizeof(client_result),0);
  large_csidh(&client_result, &client_result, &unblind);
  /////// Uncomment for sanity
  puts("FINAL RESULT");
  uint_print(&client_result.A); 
  clock_gettime(CLOCK_REALTIME, &now);
  end= now.tv_sec + now.tv_nsec*1e-9;
  time_stamp[runs] = (end-start)*1000; // mult with 1000 to get ms	
  overall +=(end-start);
  printf("OPRF Evaluation took %.3lf s\n", overall); 
  
  }
  // Not from original impl
  // Measure Network Traffic
  int byteSizeSent = 0;
  int byteSizeRecv = 0;
  int csocket = socket(AF_INET, SOCK_STREAM, 0);
  while (connect(csocket, (struct sockaddr *)&s,
        sizeof(struct sockaddr)) < 0);
  clock_gettime(CLOCK_REALTIME, &now);
  start= now.tv_sec + now.tv_nsec*1e-9;
  bool msg[HASHLEN];
  for(size_t i=0; i<HASHLEN; i++)
    msg[i]=(bool)(rand()%2);
  // OPRF execution
  large_private_key unblind={0};
  public_key client_result={0}; 
  for(size_t i=0; i<HASHLEN; ++i){
    private_key blinder={0};
    csidh_private(&blinder);
    csidh(&client_result, &client_result, &blinder);
    byteSizeSent += sizeof(client_result);
    send(csocket, &client_result, sizeof(client_result),0);
    sub_large_key(&unblind, &blinder);
    Response response;
    recv(csocket, &response, sizeof(response),0);
    byteSizeRecv += sizeof(response);
    if(msg[i]){
      // unblind and update
      memcpy(&client_result, &response.E[1], sizeof(public_key));
    }
    else{
      memcpy(&client_result, &response.E[0], sizeof(public_key));
    }
  }
  private_key blinder={0};
  csidh_private(&blinder);
  csidh(&client_result, &client_result, &blinder); 
  send(csocket, &client_result, sizeof(client_result),0);
  byteSizeSent += sizeof(client_result);
  sub_large_key(&unblind, &blinder);
  recv(csocket, &client_result, sizeof(client_result),0);
  byteSizeRecv += sizeof(client_result);
  large_csidh(&client_result, &client_result, &unblind);
    
  // Print all results
  sprintf(output_text + strlen(output_text),"[");
  for(size_t i = 0; i < nrIterations-1; ++i){
  	sprintf(output_text + strlen(output_text),"%.3lf, ", time_stamp[i]);
  }
  if (nrIterations > 0){
  	sprintf(output_text + strlen(output_text),"%.3lf",time_stamp[nrIterations-1]);
  }
  sprintf(output_text + strlen(output_text),"]\n");
  
  //Print average and deviation
  double avg = 0;
  for (size_t i =0; i < nrIterations; ++i){
  	avg += time_stamp[i];
  }
  avg /= nrIterations;
  sprintf(output_text + strlen(output_text),"Average Time [ms]: %.3lf\n", avg);
  double variance = 0;
  for (size_t i =0; i < nrIterations; ++i){
  	variance += (time_stamp[i] - avg)*(time_stamp[i] - avg);
  }
  variance /= nrIterations;
  double standard_deviation = sqrt(variance);
  sprintf(output_text + strlen(output_text),"Standard Deviation [ms]: %.3lf\n", standard_deviation);
  printf("length of output text: %d", strlen(output_text));
  
  sprintf(output_text + strlen(output_text),"Measured traffic for the run:\n");
  sprintf(output_text + strlen(output_text),"Measured Traffic sent [Bytes]: %d\n",byteSizeSent); 
  sprintf(output_text + strlen(output_text),"Measured Traffic received [Bytes]: %d\n",byteSizeRecv);
  sprintf(output_text + strlen(output_text),"Measured Traffic total[Bytes]: %d\n",byteSizeSent + byteSizeRecv);
      
  //Write to file
  char filename[100];
  sprintf(filename, "OPUS_benchmark_results_%d-%d-%d_%d_%d.txt",(timeinfo->tm_year+1900),(timeinfo->tm_mon+1),timeinfo->tm_mday,timeinfo->tm_hour,timeinfo->tm_min);
  FILE *fptr;
  fptr = fopen(filename,"w");
  if(fptr == NULL){
      printf("Error!");   
      exit(1);         
  }
  fprintf(fptr,"%s",output_text);
  fclose(fptr);

  return 0; 
}

