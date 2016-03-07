/*
 * Adapted from: https://raw.githubusercontent.com/mmaker/bachelor/master/src/questions/include/qwiener.h
 */
#ifndef _WIENER_H_
#define _WIENER_H_
/**
 * Fractions made of bignums.
 */
typedef struct bigfraction {
	BIGNUM* h;   /**< numerator */
	BIGNUM* k;   /**< denominator */
} bigfraction_t;

typedef struct cf {
	bigfraction_t fs[3];
	short i;
	bigfraction_t x;
	BIGNUM* a;
	BN_CTX* ctx;
} cf_t;

/* continued fractions utilities. */
cf_t* cf_init(BN_CTX *ctx, BIGNUM* num, BIGNUM* den);

void cf_free(cf_t* f);

bigfraction_t* cf_next(cf_t *f);

#endif /* _WIENER_H_ */
