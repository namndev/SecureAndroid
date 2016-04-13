#include "ProcHmac.hxx"
#define A(c)            (c) - 0x19
#define UNHIDE_STR(str) do { char *p = str;  while (*p) *p++ += 0x19; } while (0)
#define HIDE_STR(str)   do { char *p = str;  while (*p) *p++ -= 0x19; } while (0)

#define ALGORITHM  "HmacSHA512"

JavaVM* ProcHmac::mVm = 0;
jclass ProcHmac::mMacClass = 0;
jclass ProcHmac::mSecretKeySpecClass = 0;
jstring ProcHmac::jstrAlgorithm = NULL;

ProcHmac::ProcHmac() {
}

ProcHmac::~ProcHmac() {
}

void ProcHmac::setupVm(JavaVM* vm) {
	mVm = vm;
	JNIEnv * env;
	// cache class that cant be found inside native thread because of ClassLoader issue
	mVm->GetEnv((void**) &env, JNI_VERSION_1_6);
	mMacClass = env->FindClass("javax/crypto/Mac");
	mSecretKeySpecClass = env->FindClass("javax/crypto/spec/SecretKeySpec");

	mMacClass = (jclass) env->NewGlobalRef(mMacClass);
	mSecretKeySpecClass = (jclass) env->NewGlobalRef(mSecretKeySpecClass);
	jstrAlgorithm = env->NewStringUTF(ALGORITHM);
	jstrAlgorithm = (jstring) env->NewGlobalRef(jstrAlgorithm);
}
void ProcHmac::attachThread(JNIEnv** env) {
	// TODO: sometimes we're already running jvm thread
	// therefore there's no need to atttach/detach
	ProcHmac::mVm->AttachCurrentThread(env, 0);
}

void ProcHmac::detachThread() {
	// TODO: sometimes we're already running jvm thread
	// therefore there's no need to atttach/detach
	ProcHmac::mVm->DetachCurrentThread();
}

int ProcHmac::min(int x, int y)
{
	return y ^ ((x ^ y) & -(x < y));
}

/*Function to find maximum of x and y*/
int ProcHmac::max(int x, int y)
{
	return x ^ ((x ^ y) & -(x < y));
}

char* ProcHmac::buildSecretKey(const char* number)
{
	 char str[] = {
	    A('B'), A('8'), A('Y'), A('6'), A('t'), A('i'), A('M'), A('1'), A('U'), A('7'), A('M'),
	    A('P'), A('p'), A('U'), A('a'), A('U'), A('o'),A('O'), A('n'), A('P'), A('6'), A('_'),
		A('V'), A('z'), A('p'),0
	  };
	UNHIDE_STR(str);
	const char* secKey = str;
	int j = 0;
	int secLen = strlen(secKey);
	int numberLen = strlen(number);
	int totalLeng = secLen + numberLen;
	char* result;
	result = (char*) malloc(sizeof(char) * (totalLeng + 1));
	int maxLeng = max(secLen,numberLen);
	for(int i = 0; i < maxLeng; i++)
	{
			if (i < secLen) {
				result[j] = secKey[i];
				j++;
			}
			if (i < numberLen){
				result[j] = number[i];
				j++;
			}
	 } // end for
	result[totalLeng] = '\0';
	HIDE_STR(str);
	return result;
}

jbyteArray ProcHmac::hmacSHA512(const std::string& msisdn, const std::string& msg, const char* hash)
{
	char str[] = {
		    A('1'), A('I'), A('C'), A('2'), A('Z'),
		    A('7'), A('z'), A('f'), A('q'), A('p'), A('9'),A('9'), A('6'), A('D'), A('X'), A('a'),
			A('s'), A('k'), A('v'), A('8'), A('x'),A('u'), A('d'), A('S'), A('k'), A('y'),
			A('8'), A('='),0
		};
	UNHIDE_STR(str);
	if(strcmp(hash,str) != 0)
	{
		HIDE_STR(str);
		return NULL;
	}
	else
	{
		HIDE_STR(str);
	}
	JNIEnv * env;
	attachThread(&env);
	// get buildKey
	const char* number = msisdn.c_str();
	char* secretChar = buildSecretKey(number);
	int secLeng = strlen(secretChar);
	jbyteArray secret = (env)->NewByteArray(secLeng);
	env->SetByteArrayRegion(secret, 0, secLeng, reinterpret_cast<jbyte*>(secretChar));

	//init
	//secret
	jmethodID secret_constructor = env->GetMethodID(mSecretKeySpecClass, "<init>", "([BLjava/lang/String;)V");
	jobject myKey = env->NewObject(mSecretKeySpecClass, secret_constructor, secret, jstrAlgorithm);
	//mac
	jmethodID mac_instance = env->GetStaticMethodID(mMacClass, "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Mac;");
	jobject mac_object = env->CallStaticObjectMethod(mMacClass, mac_instance,jstrAlgorithm);
	mac_object = env->NewGlobalRef(mac_object);
	// init mac
	jmethodID mac_init = env->GetMethodID(mMacClass, "init", "(Ljava/security/Key;)V");
	env->CallVoidMethod(mac_object,mac_init,myKey);
	// doFinal
	jmethodID do_final_id =env->GetMethodID(mMacClass, "doFinal", "([B)[B");
	jbyteArray msgData = env->NewByteArray(msg.length());
	env->SetByteArrayRegion(msgData, 0, msg.length(), (jbyte*)msg.c_str());
	jbyteArray jResult = reinterpret_cast<jbyteArray>(env->CallObjectMethod(mac_object, do_final_id, msgData));

	// function DeleteLocalRef,
	// In this very moment memory not free
	env->DeleteLocalRef(myKey);
	env->DeleteLocalRef(secret);
	env->DeleteLocalRef(msgData);
	//
	env->DeleteGlobalRef(mac_object);
	return jResult;
}
