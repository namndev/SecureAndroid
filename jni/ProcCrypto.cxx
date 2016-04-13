#include "ProcCrypto.h"

#include <sstream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/md5.h>
#include <openssl/pem.h>

ProcCrypto* ProcCrypto::instance = NULL;

ProcCrypto::ProcCrypto(void){
	mCertRequestPEM = initCrypto();
}
ProcCrypto::~ProcCrypto(void){

}
ProcCrypto* ProcCrypto::Get() {
	if (!instance) {
		instance = new ProcCrypto();
	}
	return instance;
}

const char* ProcCrypto::getCertificateRequestPEM()
{
	return mCertRequestPEM;
}
const char* ProcCrypto::getPublicKey()
{
	return mPublicKey;
}
const char* ProcCrypto::getPrivateKey()
{
	return mPrivateKey;
}

// create RSA keypair (private and public key) and use them to create Certificate Signing Request (CSR) in PEM format
char* ProcCrypto::initCrypto() {
	size_t pri_len;            // Length of private key
	size_t pub_len;            // Length of public key
	char   *pri_key;           // Private key
	char   *pub_key;           // Public key

	int ret = 0;
	EVP_PKEY *pkey = NULL;
	pkey = EVP_PKEY_new();
	RSA * rsa;
	char *pem = NULL;
	rsa = RSA_generate_key(1024, /* number of bits for the key - 2048 is a sensible value */
						   RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
						   NULL, /* callback - can be NULL if we aren't displaying progress */
						   NULL /* callback argument - not needed in this case */
	);
	EVP_PKEY_assign_RSA(pkey, rsa);
	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_PrivateKey(pri, pkey, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_PUBKEY(pub, pkey);

	pri_len = BIO_pending(pri);
	pri_key = (char *) malloc(pri_len + 1);
	BIO_read(pri, pri_key, pri_len);
	pri_key[pri_len] = '\0';
	// set private key
	mPrivateKey = pri_key;


	pub_len = BIO_pending(pub);
	pub_key = (char *) malloc(pub_len + 1);
	BIO_read(pub, pub_key, pub_len);
	pub_key[pub_len] = '\0';
	// set public key
	mPublicKey = pub_key;

	BIO_free_all(pub);
	BIO_free_all(pri);

	rsa = NULL;
	X509_REQ * x509;
	x509 = X509_REQ_new();
	ret = X509_REQ_set_pubkey(x509, pkey);
	if (ret != 1) {
		X509_REQ_free(x509);
		EVP_PKEY_free(pkey);
		return pem;
	}
	X509_NAME * name = X509_REQ_get_subject_name(x509);

	ret = X509_NAME_add_entry_by_txt(name, "VN", MBSTRING_ASC,
			(unsigned char *) "ff2-users.madmanteam.vn", -1, -1, 0);
	if (ret != 1) {
		X509_REQ_free(x509);
		EVP_PKEY_free(pkey);
		return pem;
	}

	ret = X509_REQ_set_subject_name(x509, name);
	if (ret != 1) {
		X509_REQ_free(x509);
		EVP_PKEY_free(pkey);
		return pem;
	}
	ret = X509_REQ_sign(x509, pkey, EVP_sha1());
	if (ret <= 0) {
		X509_REQ_free(x509);
		EVP_PKEY_free(pkey);
		return pem;
	}

	BIO *bio = NULL;

	if (NULL == x509) {
		X509_REQ_free(x509);
		EVP_PKEY_free(pkey);
		return pem;
	}
	bio = BIO_new(BIO_s_mem());
	if (NULL == bio) {
		X509_REQ_free(x509);
		EVP_PKEY_free(pkey);
		return pem;
	}
	if (0 == PEM_write_bio_X509_REQ(bio, x509)) {
		BIO_free_all(bio);
		X509_REQ_free(x509);
		EVP_PKEY_free(pkey);
		return pem;
	}
	pem = (char *) malloc(bio->num_write + 1);
	if (NULL == pem) {
		BIO_free_all(bio);
		X509_REQ_free(x509);
		EVP_PKEY_free(pkey);
		return pem;
	}
	int count = (int) bio->num_write;
	memset(pem, 0, count + 1);
	BIO_read(bio, pem, count);

	BIO_free_all(bio);
	RSA_free(rsa);
	//
	X509_REQ_free(x509);
	EVP_PKEY_free(pkey);
	return pem;
}

