#ifndef PROCHMAC_HXX
#define PROCHMAC_HXX
#include <string>
#include <jni.h>


class ProcHmac
{
public:
	ProcHmac();
	virtual ~ProcHmac();
	  /**
	   * Keeps a handle to VM
	   */
	  static void setupVm(JavaVM* vm);
	  /**
	     * dettach thread
	     */
	  void detachThread();
	  // hmac
	  jbyteArray hmacSHA512(const std::string& msisdn,const std::string& msg, const char* hash);
private:
	  /**
	   * attach thread
	   */
	  void attachThread(JNIEnv** env);

	  /*Function to find minimum of x and y*/
	  int min(int x, int y);

	  /*Function to find maximum of x and y*/
	  int max(int x, int y);
	  // genkey
	  char* buildSecretKey(const char* number);

private: // data

  /// vm  handler
  static JavaVM* mVm;

  /// SecretKeySpec java class
  static jclass mSecretKeySpecClass;

  /// Mac java class
  static jclass mMacClass;

  static jstring jstrAlgorithm;

};
#endif // PROCHMAC_HXX
