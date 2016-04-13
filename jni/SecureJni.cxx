// Copyright (c) 2016 MADMAN

#include "SecureJni.h"
#include "ProcHmac.hxx"
#include "ProcCrypto.h"
using namespace std;

jint JNI_OnLoad(JavaVM* vm, void* reserved) {
	JNIEnv *env = NULL;
	jint result = -1;

	if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
		// ERROR: GetEnv failed.
		return result;
	}
	result = JNI_VERSION_1_6;
	ProcHmac::setupVm(vm);
	return result;
}

/*
 * Class:     com_madman_native_SecureJni
 * Method:    hmacSHA512
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_madman_native_SecureJni_hmacSHA512(
		JNIEnv *env, jobject job, jstring msisdn, jstring msg, jstring hash){
	const char* number = env->GetStringUTFChars(msisdn,NULL);
	const char* msgchar = env->GetStringUTFChars(msg,NULL);
	const char* hashchar = env->GetStringUTFChars(hash,NULL);
	ProcHmac hm;
	return hm.hmacSHA512(string(number),string(msgchar),hashchar);
}
/*
 * Class:     com_madman_native_SecureJni
 * Method:    certificatePEM
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_madman_native_SecureJni_certificatePEM(
		JNIEnv *env, jobject) {
	const char* certPEM = ProcCrypto::Get()->getCertificateRequestPEM();
	jstring jstr = (env)->NewStringUTF(certPEM);
	return jstr;
}

/*
 * Class:     com_madman_native_SecureJni
 * Method:    publicKey
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_madman_native_SecureJni_publicKey(
		JNIEnv *env, jobject){
	const char* pubKey = ProcCrypto::Get()->getPublicKey();
	jstring jstr = (env)->NewStringUTF(pubKey);
	return jstr;
}

/*
 * Class:     com_madman_native_SecureJni
 * Method:    privateKey
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_madman_native_SecureJni_privateKey(
		JNIEnv *env, jobject){
	const char* privKey = ProcCrypto::Get()->getPrivateKey();
	jstring jstr = (env)->NewStringUTF(privKey);
	return jstr;
}