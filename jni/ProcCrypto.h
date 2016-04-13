#ifndef PROC_CRYPTO_H
#define PROC_CRYPTO_H

class ProcCrypto {
public:
	ProcCrypto(void);
	virtual ~ProcCrypto(void);
	static ProcCrypto* Get();
	const char* getCertificateRequestPEM();
	const char* getPublicKey();
	const char* getPrivateKey();
private:
	char* initCrypto();
private:
	static ProcCrypto* instance;
	char* mCertRequestPEM;
	char* mPrivateKey;
	char* mPublicKey;
};
#endif
