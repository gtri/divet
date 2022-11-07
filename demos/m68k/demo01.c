/* This demo simply makes upper case letters from lower case letters. */

#include<string.h>

char *lower_case = "abcdefghijklmnopqrstuvwxyz";
char upper_case[26];

int main() {
	int  idx = 0;
	char tmp = lower_case[idx];
	while( tmp != 0 ) {	
		upper_case[idx] = tmp + 32;
		tmp = lower_case[++idx];
	}
	return 0;
}
