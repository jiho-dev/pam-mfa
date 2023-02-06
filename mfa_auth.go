package main

/*
#include <security/pam_appl.h>
*/
import "C"
import (
	"fmt"
	"pam_mfa/yubico_otp"
	"strings"

	"github.com/dgryski/dgoogauth"
)

func authenticateYubicoOTP(pamh *C.pam_handle_t, yubico_otp_id string) bool {
	yubiAuth, err := yubico_otp.NewYubiAuth(yubicoOtpId, yubicoOtpSecret)
	if err != nil {
		pamLog("Unable to setup Yubico OTP Auth")
		return false
	}
	otp := strings.TrimSpace(requestPass(pamh, C.PAM_PROMPT_ECHO_OFF, "YubiKey OTP: "))
	if !strings.HasPrefix(otp, yubico_otp_id) {
		return false
	}
	ok, err := yubiAuth.VerifyOTP(otp)
	if err != nil {
		fmt.Printf("%s\n", err)
		return false
	}
	return ok
}

func authenticateTOTP(pamh *C.pam_handle_t, totp_secret string) bool {
	totp_secret = strings.ToUpper(totp_secret)
	totp_config := dgoogauth.OTPConfig{
		Secret:     totp_secret,
		WindowSize: totpWindow,
		UTC:        true,
	}

	totp_code := strings.TrimSpace(requestPass(pamh, C.PAM_PROMPT_ECHO_OFF, "TOTP: "))
	ok, err := totp_config.Authenticate(totp_code)
	if err != nil {
		return false
	}

	return ok

}

func authenticateTOTP1(pamh *C.pam_handle_t, totp_secret string) bool {
	totp_secret = strings.ToUpper(totp_secret)
	totp_config := dgoogauth.OTPConfig{
		Secret:     totp_secret,
		WindowSize: totpWindow,
		UTC:        true,
	}
	pamLog("totp config: %+v", totp_config)

	passwd := strings.TrimSpace(requestPass(pamh, C.PAM_PROMPT_ECHO_OFF, "Password: "))
	pamLog("input password: %s", passwd)

	totp_code := strings.TrimSpace(requestPass(pamh, C.PAM_PROMPT_ECHO_OFF, "TOTP: "))
	pamLog("TOTP: %s", totp_code)
	/*
		ok, err := totp_config.Authenticate(totp_code)
		if err != nil {
			return false
		}

		return ok
	*/

	return true
}
