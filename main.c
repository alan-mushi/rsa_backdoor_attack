#include <openssl/bn.h>
#include <openssl/bio.h>
#include <stdio.h>

#include "wiener.h"

BIO *bio_out = NULL;

BIGNUM *temp = NULL, *temp2 = NULL; // Keep a light memory footprint

static void print_BN(const char* varname, BIGNUM *var) {
	char *repr_bn = NULL;

	if (bio_out == NULL)
		bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	repr_bn = BN_bn2dec(var);
	BIO_printf(bio_out, "\n[RSA backdoor attack] %s = %s\n", varname, repr_bn);
	OPENSSL_free(repr_bn);
}

/*
 * Compute 'dprime' from 'eprime' and 'n' using Wiener's attack.
 */
static int compute_dprime(BIGNUM *n, BIGNUM *eprime, BIGNUM *dprime,
							BN_CTX *ctx) {
	int res = EXIT_FAILURE, t = -1;

	cf_t *cf = NULL;
	bigfraction_t *it = NULL;

	BIGNUM *M = NULL, *C = NULL;

	// Here we maintain the names of variables used in the paper but 'M' may be
	// renamed.
	if ((M = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((C = BN_CTX_get(ctx)) == NULL)
		goto err;

	// convert(eprime / n, confrac, 'reduites'):
	if ((t = BN_num_bits(n)) == -1)
		goto err;
	if ((cf = cf_init(ctx, eprime, n)) == NULL)
		goto err;

	// M := 12345:
	if (BN_dec2bn(&M, "12345") == 0)
		goto err;

	// C := M &^ eprime mod n:
	if (BN_mod_exp(C, M, eprime, n, ctx) == 0)
		goto err;

	// while C &^ denom(reduites[i]) mod n <> M do i := i+1: od:
	do {
		if ((it = cf_next(cf)) == NULL)
			goto err;
		if (BN_mod_exp(temp, C, it->k, n, ctx) == 0)
			goto err;
	} while (BN_cmp(temp, M) != 0);

	// dprime := denom(reduites[i])
	if (BN_copy(dprime, it->k) == NULL)
		goto err;

	res = EXIT_SUCCESS;

err:
	if (cf != NULL)
		cf_free(cf);

	return res;
}

/*
 * Compute 'b' from 'n', 'eprime' and 'dprime'.
 */
static int compute_b(BIGNUM *n, BIGNUM *eprime, BIGNUM *dprime, BIGNUM *b,
						BN_CTX *ctx) {
	int res = EXIT_FAILURE;

	BIGNUM	*u = NULL, *quot = NULL, *a = NULL,
			*b2 = NULL;

	if ((u = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((quot = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((a = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((b2 = BN_CTX_get(ctx)) == NULL)
		goto err;

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
		// quot = u / 2 ; temp = u % 2
		if (BN_div(quot, temp, u, temp2, ctx) == 0)
			goto err;
	}

	/*
	 * The range is inclusive in the paper but we can only get a number in:
	 * 0 <= rnd < max with BN_pseudo_rand_range().
	 */
	if (BN_copy(temp, n) == NULL) // temp = n
		goto err;
	// Note: we could reuse 'temp2' but it is easier this way.
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
		if (BN_copy(b, b2) == NULL)
			goto err;
		if (BN_mod_mul(b2, b, b, n, ctx) == 0)
			goto err;
	}

	res = EXIT_SUCCESS;

err:
	return res;
}

/*
 * Compute 'p' and 'q' from 'b' and 'n'.
 */
static int compute_p1_and_q1(BIGNUM *n, BIGNUM *b, BIGNUM *p1, BIGNUM *q1,
								BN_CTX *ctx) {
	int res = EXIT_FAILURE;

	// p1 := igcd(b-1, n);
	if (BN_sub(temp, b, BN_value_one()) == 0) // temp = b-1
		goto err;
	if (BN_gcd(p1, temp, n, ctx) == 0)
		goto err;

	// q1 := igcd(b+1, n);
	if (BN_add(temp, b, BN_value_one()) == 0) // temp = b+1
		goto err;
	if (BN_gcd(q1, temp, n, ctx) == 0)
		goto err;

	/*
	 * If the computation is correct this will never fail.
	 */
	// assert(n - p1 * q1 == 0)
	if (BN_mul(temp, p1, q1, ctx) == 0) // temp = p1 * q1
		goto err;
	if (BN_sub(temp2, n, temp) == 0)
		goto err;
	if (BN_is_zero(temp2) == 0) {
		fprintf(stderr, "n - p1 * q1 != 0");
		goto err;
	}

	res = EXIT_SUCCESS;

err:
	return res;
}

/*
 * Recover the private exponent 'd' from 'p' and 'q'.
 */
static int compute_d2(BIGNUM *p1, BIGNUM *q1, BIGNUM *e, BIGNUM *d2, BN_CTX *ctx) {
	int res = EXIT_FAILURE;

	BIGNUM *phi1 = NULL;

	if ((phi1 = BN_CTX_get(ctx)) == NULL)
		goto err;

	// phi1 := (p1-1)*(q1-1):
	if (BN_sub(temp, p1, BN_value_one()) == 0)
		goto err;
	if (BN_sub(temp2, q1, BN_value_one()) == 0)
		goto err;
	if (BN_mul(phi1, temp, temp2, ctx) == 0)
		goto err;

	// igcdex(e, phi1, 'd2')
	if (BN_gcd(temp, e, phi1, ctx) == 0)
		goto err;
	if (BN_is_one(temp) != 1) {
		fprintf(stderr, "gcd(e, phi1) != 1\n");
		goto err;
	}
	if (BN_mod_inverse(temp, e, phi1, ctx) == NULL)
		goto err;

	// d2 := d2 mod phi1:
	if (BN_mod(d2, temp, phi1, ctx) == 0)
		goto err;

	res = EXIT_SUCCESS;

err:
	return res;
}

int main(int argc, char *argv[]) {
	int ok = EXIT_FAILURE;

	BN_CTX *ctx = NULL;

	BIGNUM	*M = NULL, *e = NULL, *eprime = NULL, *n = NULL, *dprime = NULL,
			*b = NULL, *p1 = NULL, *q1 = NULL, *d2 = NULL;

	if (argc != 4) {
		fprintf(stderr, "usage:\t%s M n e\n\n", argv[0]);
		fprintf(stderr, "\tM\tThe value of the trapdoor\n");
		fprintf(stderr, "\tn\tThe modulus\n");
		fprintf(stderr, "\te\tThe public exponent\n");
		goto err;
	}

	// Example values:
	// const char *M_str = "44942328371557897693232629769725618340449424473557664318357520289433168951375240783177119330601884005280028469967848339414697442203604155623211857659868531094441973356216371319075554900311523529863270738021251442209537670585615720368478277635206809290837627671146574559986811484619929076208839082406056034304";
	// const char *n_str = "134591307025834373041087325782561308830434586901549689674754291106755102264983761738128412798840544908351239450526266817483329752099241689761944305879497936977719187267863983780322320900993767491623779984637485812052659925559869906499917125993208602201694239500254832743974389852205055414037159935773695441649";
	// const char *e_str = "108242225340017775490899344991285570157365902845743035196919897638600831711621181802400254400582795910137863089836585954648548156115434588509142823248669210932335212123304731178495639025435750255156901231626282309435477118201204970234610783318760953810297869926278430441502426159261620736769265537607775797761";
	const char *M_str = argv[1];
	const char *n_str = argv[2];
	const char *e_str = argv[3];

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;

	BN_CTX_start(ctx);

	if ((M = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((e = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((eprime = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((n = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((dprime = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((b = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((p1 = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((q1 = BN_CTX_get(ctx)) == NULL)
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

	print_BN("M", M);
	print_BN("n", n);
	print_BN("e", e);

	// eprime := e - M
	if (BN_sub(eprime, e, M) == 0)
		goto err;

	if (compute_dprime(n, eprime, dprime, ctx) == EXIT_FAILURE)
		goto err;

	if (compute_b(n, eprime, dprime, b, ctx) == EXIT_FAILURE)
		goto err;

	if (compute_p1_and_q1(n, b, p1, q1, ctx) == EXIT_FAILURE)
		goto err;

	print_BN("p1", p1);
	print_BN("q1", q1);

	if (compute_d2(p1, q1, e, d2, ctx) == EXIT_FAILURE)
		goto err;

	print_BN("d2", d2);
	ok = EXIT_SUCCESS;

err:
	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}

	return ok;
}
