//go:build darwin || linux
// +build darwin linux

package main

/*
#include <security/pam_appl.h>
*/
import "C"
import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"os/user"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	configFile      = ".mfa.yml"
	yubicoOtpId     = ""
	yubicoOtpSecret = ""
	totpWindow      = 5
)

type AuthResult int

const (
	AuthError AuthResult = iota
	AuthSuccess

	LogName = "pam-spc"
)

func pamLog(format string, args ...interface{}) {
	l, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, LogName)
	if err != nil {
		return
	}

	l.Warning(fmt.Sprintf(format, args...))
}

func authenticate(pamh *C.pam_handle_t, uid int, username string) AuthResult {
	origEUID := os.Geteuid()
	if os.Getuid() != origEUID || origEUID == 0 {
		if !seteuid(uid) {
			pamLog("error dropping privs from %d to %d", origEUID, uid)
			return AuthError
		}
		defer func() {
			if !seteuid(origEUID) {
				pamLog("error resetting uid to %d", origEUID)
			}
		}()
	}
	usr, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		pamLog("error looking for user %d", uid)
		return AuthError
	}
	config, err := ReadYAML(path.Join(usr.HomeDir, configFile))
	if err != nil {
		pamLog("error reading configuration file")
		return AuthError
	}
	auth_pref := config["auth_preference"].([]interface{})
	if len(auth_pref) == 0 {
		pamLog("MFA is not configured for user %s, so access denied.", usr.Username)
		return AuthError
	}
	pamLog("Start MFA challenge for user %s", usr.Username)
	for _, amthd := range auth_pref {
		auth_method := amthd.(string)
		auth_result := false
		switch auth_method {
		case "yubico_otp":
			auth_result = authenticateYubicoOTP(pamh, config["yubico_otp_id"].(string))
		case "totp":
			//auth_result = authenticateTOTP(pamh, config["totp_key"].(string))
			auth_result = authenticateTOTP1(pamh, config["totp_key"].(string))
		}
		if auth_result {
			pamLog("User %s passed MFA method %s.", usr.Username, auth_method)
			return AuthSuccess
		} else {
			pamLog("User %s failed MFA method %s, turning to next method", usr.Username, auth_method)
		}
	}
	pamLog("All MFA methods failed for user %s.", usr.Username)
	return AuthError
}

func pamAuthenticate(pamh *C.pam_handle_t, uid int, username string, argv []string) AuthResult {
	runtime.GOMAXPROCS(1)

	for i, arg := range argv {
		pamLog("arg: %d, %s", i, arg)

		opt := strings.SplitN(arg, "=", 2)
		switch opt[0] {
		case "yubico_otp_id":
			yubicoOtpId = opt[1]
		case "yubico_otp_secret":
			yubicoOtpSecret = opt[1]
		case "totp_window":
			totpWindow, _ = strconv.Atoi(opt[1])
		}
	}

	return authenticate(pamh, uid, username)
}

func getPassword() []byte {
	if terminal.IsTerminal(0) {
		fmt.Fprintf(os.Stderr, "Enter Password: ")
		pass, err := gopass.GetPasswd()
		if err != nil {
			log.Fatal(err)
		}
		return bytes.TrimSpace(pass)
	} else {
		pass, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		return bytes.TrimSpace(pass)
	}
}

func main() {
	//password := getPassword()
	password := string("admin123!")

	crypters := []int{HASH_MD5, HASH_BLOWFISH, HASH_SHA256, HASH_SHA512}

	for _, idx := range crypters {
		fmt.Printf("Crypto ID: %d \n", idx)

		hash, err := HashPassword(idx, password, "")
		if err != nil {
			fmt.Printf("1. failed to encrypt password: %s \n", err)
		} else {
			fmt.Printf("1. password hash: %s, %s \n", password, hash)
		}

		//c, err := crypter(HASH_BLOWFISH)
		if VerifyPassword(password, hash) {
			fmt.Printf("2. correct hash: %s, %s \n", password, hash)
		} else {
			fmt.Printf("2. incorrect hash: %s, %s \n", password, hash)
		}

	}

}
