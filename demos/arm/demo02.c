/* This demo performs atol on 1-5 and calculates the factorial of each */

#include<stdio.h>

int argc = 5;
char* argv[] = {"1","2","3","4","5"};

long atol(char* s) {
	long result = 0;
	int neg = 0;
	if( *s == '-' ) {
		s++;
		neg = 1;
	}
	while( *s ) {
		result = (result*10) + (*s - '0');
		s++;
	}
	if( neg ) {
		result = result * -1;
	}
	return result;
}

long fact(long n) {
	if( n == 1 ) {
		return 1;
	}
	else {
		return n * fact(n-1);
	}
}

int main() {
	long n;
	int i;
	for( i=0;i<argc;i++ ) {
		n = atol(argv[i]);
		printf("fact(%ld) = %ld\n",n,fact(n));
	}
	return 0;
}
