#include <openssl/bn.h>
#include <openssl/bio.h>
#include <stdio.h>

#include "wiener.h"

int main() {
	int ok = EXIT_FAILURE, i, t = -1;
	BN_CTX *ctx = NULL;
	BIO *bio_out;

	BIGNUM	*M = NULL, *e = NULL, *eprime = NULL, *n = NULL, *dprime = NULL,
			*C = NULL, *u = NULL, *quot = NULL, *a = NULL, *b = NULL,
			*b2 = NULL, *p1 = NULL, *q1 = NULL, *phi1 = NULL, *d2 = NULL,
			*temp = NULL, *temp2 = NULL;
	
	const char *M_str = ""; // TODO: fill
	const char *n_str = ""; // TODO: fill
	const char *e_str = ""; // TODO: fill
	char *repr_BN = NULL;

	cf_t *cf;
	bigfraction_t *it;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto err;

	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	if ((M = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((e = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((eprime = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((n = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((C = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((dprime = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((u = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((quot = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((a = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((b = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((b2 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((p1 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((q1 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((phi1 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((d2 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((temp = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((temp2 = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (BN_dec2bn(&M, M_str) == 0)
		goto err;
	if (BN_dec2bn(&n, n_str) == 0)
		goto err;
	if (BN_dec2bn(&e, e_str) == 0)
		goto err;

	// eprime := e - M
	if (BN_sub(eprime, e, M) == 0)
		goto err;

	// convert(eprime / n, confrac, 'reduites'):
	if ((t = BN_num_bits(n)) == -1)
		goto err;
	if ((cf = cf_init(NULL, eprime, n)) == NULL)
		goto err;

	// M := 12345:
	if (BN_dec2bn(&M, "12345") == 0)
		goto err;

	// C := M &^ eprime mod n:
	if (BN_mod_exp(C, M, eprime, n, ctx) == 0)
		goto err;

	// while C &^ denom(reduites[i]) mod n <> M do i := i+1: od:
	if ((it = cf_next(cf)) == NULL)
		goto err;
	if (BN_mod_exp(temp, C, it->k, n, ctx) == 0)
		goto err;

	for (i = 1; it && BN_cmp(temp, M) != 0; i++, it = cf_next(cf)) {
		if (BN_mod_exp(temp, C, it->k, n, ctx) == 0)
			goto err;
	}

	// dprime := denom(reduites[i])
	if (BN_copy(dprime, it->k) == NULL)
		goto err;

	// We don't need 'reduites' from now on
	cf_free(cf);
	cf = NULL;

	// print(dprime)
	repr_BN = BN_bn2dec(dprime);
	BIO_printf(bio_out, "\n[RSA backdoor attack] dprime = %s\n", repr_BN);
	OPENSSL_free(repr_BN);
	
	// u := eprime * dprime - 1:
	if (BN_mul(temp, eprime, dprime, ctx) == 0)
		goto err;
	if (BN_sub(u, temp, BN_value_one()) == 0)
		goto err;

	// while irem(u, 2, 'quot') = 0 do u := quot od:
	if (BN_add(temp2, BN_value_one(), BN_value_one()) == 0) // temp2 = 2
		goto err;
	if (BN_div(quot, temp, u, temp2, ctx) == 0) // quot = u / 2 ; temp = u % 2
		goto err;

	while (BN_is_zero(temp) == 1) {
		if (BN_copy(u, quot) == NULL) // u = quot
			goto err;
		if (BN_div(quot, temp, u, temp2, ctx) == 0) // quot = u / 2 ; temp = u % 2
			goto err;
	}

	/*
	 * The range is inclusive in the paper but we can only get a number in:
	 * 0 <= rnd < max with BN_pseudo_rand_range().
	 */
	if (BN_copy(temp, n) == NULL) // temp = n
		goto err;
	if (BN_sub_word(temp, (BN_ULONG) 2) == 0) // temp = n - 2
		goto err;

	// while igcd(a, n) <> 1 do a := rand(2..n-1)(); od:
	do {
		// a := rand(2..n-1)():
		if (BN_pseudo_rand_range(a, temp) == 0)
			goto err;
		if (BN_add_word(a, (BN_ULONG) 2) == 0)
			goto err;
		if (BN_gcd(temp2, a, n, ctx) == 0)
			goto err;
	} while (BN_is_one(temp2) == 0);

	// b := a &^ u mod n:
	if (BN_mod_exp(b, a, u, n, ctx) == 0)
		goto err;

	// b2 := b * b mod n:
	if (BN_mod_mul(b2, b, b, n, ctx) == 0)
		goto err;

	/*
	 * while b2 <> 1 do
	 * 	b := b2:
	 * 	b2 := b * b mod n:
	 * od:
	 */
	while (BN_is_one(b2) != 1) {
		if (BN_copy(b , b2) == NULL)
			goto err;
		if (BN_mod_mul(b2, b, b, n, ctx) == 0)
			goto err;
	}

	// p1 := igcd(b-1, n);
	if (BN_sub(temp, b, BN_value_one()) == 0) // temp = b1-1
		goto err;
	if (BN_gcd(p1, temp, n, ctx) == 0)
		goto err;

	// q1 := igcd(b+1, n);
	if (BN_add(temp, b, BN_value_one()) == 0) // temp = b1+1
		goto err;
	if (BN_gcd(q1, temp, n, ctx) == 0)
		goto err;

	// print(p1, q1)
	repr_BN = BN_bn2dec(p1);
	BIO_printf(bio_out, "\n[RSA backdoor attack] p1 = %s\n", repr_BN);
	OPENSSL_free(repr_BN);
	repr_BN = BN_bn2dec(q1);
	BIO_printf(bio_out, "\n[RSA backdoor attack] q1 = %s\n", repr_BN);
	OPENSSL_free(repr_BN);

	// assert(n - p1 * q1 == 0)
	if (BN_mul(temp, p1, q1, ctx) == 0) // temp = p1 * q1
		goto err;
	if (BN_sub(temp2, n, temp) == 0)
		goto err;
	if (BN_is_zero(temp2) == 0) {
		fprintf(stderr, "n - p1 * q1 != 0");
		goto err;
	}

	// phi1 := (p1-1)*(q1-1):
	if (BN_sub(temp, p1, BN_value_one()) == 0)
		goto err;
	if (BN_sub(temp2, q1, BN_value_one()) == 0)
		goto err;
	if (BN_mul(phi1, temp, temp2, ctx) == 0)
		goto err;

	// igcdex(e, phi1, 'd2')
	if (BN_mod_inverse(temp, e, phi1, ctx) == NULL)
		goto err;

	// d2 := d2 mod phi1:
	if (BN_mod(d2, temp, phi1, ctx) == 0)
		goto err;

	// print(d2)
	repr_BN = BN_bn2dec(d2);
	BIO_printf(bio_out, "\n[RSA backdoor attack] d2 = %s\n", repr_BN);
	OPENSSL_free(repr_BN);

	ok = EXIT_SUCCESS;

err:
	if (cf != NULL)
		cf_free(cf);

	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}

	return ok;
}
