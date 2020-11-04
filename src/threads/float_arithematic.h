#ifndef FLOAT_ARITHMETIC_H
#define FLOAT_ARITHMETIC_H

#include <stdbool.h>
#include <stdint.h>

#define FORMAT 16384

extern inline int int_to_f(int n){
	return n * FORMAT;
} 

extern inline int f_to_int_floor(int x){
	return x / FORMAT;
} 

extern inline int f_to_int_round(int x){
	if(x >= 0)
      return (((x) + (FORMAT / 2)) / FORMAT );
   	else
      return (((x) - (FORMAT / 2)) / FORMAT );
} 

extern inline int add_both_f(int x, int y){
	return x + y;
} 

extern inline int sub_both_f(int x, int y){
	return x - y;
}

extern inline int add_f_i(int x, int n){
	return x + n * FORMAT;
}

extern inline int sub_f_i(int x, int n){
	return x - n * FORMAT;
}

extern inline int mult_both(int x, int y){
	return ((int64_t) x) * y / FORMAT;
}

extern inline int mult_f_i(int x, int n){
	return x * n;
}

extern inline int div_both(int x, int y){
	return ((int64_t) x) * FORMAT / y;
}

extern inline int div_f_i(int x, int n){
	return x / n;
}


#endif
