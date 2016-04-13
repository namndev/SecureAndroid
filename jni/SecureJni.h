/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_madman_native_SecureJni */

#ifndef _Included_com_madman_native_SecureJni
#define _Included_com_madman_native_SecureJni
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     com_madman_native_SecureJni
 * Method:    hmacSHA512
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_madman_native_SecureJni_hmacSHA512(
		JNIEnv *, jobject, jstring ,jstring, jstring);

/*
 * Class:     com_madman_native_SecureJni
 * Method:    certificatePEM
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_madman_native_SecureJni_certificatePEM(
		JNIEnv *, jobject);
/*
 * Class:     com_madman_native_SecureJni
 * Method:    publicKey
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_madman_native_SecureJni_publicKey(
		JNIEnv *, jobject);
/*
 * Class:     com_madman_native_SecureJni
 * Method:    privateKey
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_madman_native_SecureJni_privateKey(
		JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif
#endif
