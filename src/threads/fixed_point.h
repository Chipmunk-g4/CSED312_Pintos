#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define F (1 << 14)

#include <stdint.h>

/*
 * 해당 헤더파일은 Project 1/Problem 3에서 사용될 부동 소수점 계산을 위한 함수들을 
 * 정의해 두는 공간이다.
 * 
 * 총 11개의 부동 소수점 연산 함수가 존재한다.
 * 
 * 이때 17.14 부동소수점 형식은 int 형식을 가진다.
 * 
 * 그리고 모든 동작은 17.14 범위 내에서 작동한다 가정한다.
 */

// n: integer x,y: fixed-point numbers f: 1 for 17.14 format

// Convert n to fixed point : n * f
#define int_to_fp(n) (n) * (F)
// Convert x to integer (rounding toward zero => round down)    : x / f
#define fp_to_int_rd(x) (x) / (F)
// Convert x to integer (rounding to nearest => round off)      : (x + f / 2) / f if x >= 0, (x - f / 2) / f if x <= 0
#define fp_to_int_ro(x) (((x) >= 0)? ((x) + (F) / 2) / (F) : ((x) - (F) / 2) / (F))
// Add x and y          : x + y
#define Add_fp_fp(x,y)  (x) + (y)
// Subtract y from x    : x - y
#define Sub_fp_fp(x,y)  (x) - (y)
// Add x and n          : x + n * f
#define Add_fp_int(x,n) (x) + (n) * (F)
// Subtract n from x    : x - n * f
#define Sub_fp_int(x,n) (x) - (n) * (F)
// Multiply x by y      : ((int64_t) x) * y / f
#define Mul_fp_fp(x,y)  ((int64_t)(x)) * (y) / (F)
// Multiply x by n      : x * n
#define Mul_fp_int(x,n) (x) * (n)
// Divide x by y        : ((int64_t) x) * f / y
#define Div_fp_fp(x,y)  ((int64_t)(x)) * (F) / (y)
// Divide x by n        : x / n
#define Div_fp_int(x,n) (x) / (n)

#endif