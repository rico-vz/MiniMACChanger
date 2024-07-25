package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/AllenDang/giu"
	"github.com/charmbracelet/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type macType string

const (
	original macType = "original"
	previous macType = "previous"
)

func checkAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")

	return err == nil
}

func becomeAdmin() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 //SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		fmt.Println(err)
	}
}

func loop() {
	giu.SingleWindow().Layout(
		giu.Button("").OnClick(func() {
			log.Info("Change MAC Address button clicked")
			changeMacAddress()
		}).ID("Change MAC Address"),

		giu.Button("").OnClick(func() {
			fmt.Println("Restore original MAC Address button clicked")
			restoreMacAddress(original)
			originalAddress, err := readValueFromFile("original_address")
			if err != nil {
				log.Fatal("Failed to read original MAC Address from file. ", "Error", err)
			}
			log.Info("Original MAC Address restored. ", "Address", prettifyMacAddress(originalAddress))
		}).ID("Restore original MAC Address"),

		giu.Button("").OnClick(func() {
			fmt.Println("Restore previous MAC Address button clicked")
			restoreMacAddress(previous)
			previousAddress, err := readValueFromFile("previous_address")
			if err != nil {
				log.Fatal("Failed to read previous MAC Address from file. ", "Error", err)
			}
			log.Info("Previous MAC Address restored. ", "Address", prettifyMacAddress(previousAddress))
		}).ID("Restore previous MAC Address"),
	)
}

func main() {
	if !checkAdmin() {
		becomeAdmin()
		time.Sleep(2 * time.Second)

		os.Exit(0)

	}

	giu.NewMasterWindow("Mini MAC Changer", 640, 480, 0).Run(loop)

}

func getMacAddress() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			// Remove ":" and convert to uppercase
			a = strings.ToUpper(strings.ReplaceAll(a, ":", ""))
			as = append(as, a)
		}
	}
	return as, nil
}

func findMatchingNetworkAddress(originalAddress string) (string, error) {
	const basePath = `SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}`

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, basePath, registry.READ)
	if err != nil {
		return "", fmt.Errorf("failed to open base key: %v", err)
	}
	defer k.Close()

	for i := 0; ; i++ {
		subKeyName := fmt.Sprintf("%04d", i)
		subKey, err := registry.OpenKey(k, subKeyName, registry.READ)
		if err != nil {
			if err == registry.ErrNotExist {
				break
			}
			return "", fmt.Errorf("failed to open subkey %s: %v", subKeyName, err)
		}
		defer subKey.Close()

		networkAddress, _, err := subKey.GetStringValue("NetworkAddress")
		if err == nil && networkAddress == originalAddress {
			return fmt.Sprintf(`%s\%s`, basePath, subKeyName), nil
		}
	}

	return "", fmt.Errorf("no matching NetworkAddress found")
}

func saveValueToFile(filename string, value string) error {
	key := []byte("MMC-GoLang")
	key = append(key, make([]byte, 32-len(key))...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	encryptedValue := gcm.Seal(nonce, nonce, []byte(value), nil)
	hexEncryptedValue := hex.EncodeToString(encryptedValue)

	if filepath.Ext(filename) != ".bkp" {
		filename += ".bkp"
	}

	err = os.WriteFile(filename, []byte(hexEncryptedValue), 0644)
	if err != nil {
		return err
	}

	return nil
}

func readValueFromFile(filename string) (string, error) {
	if filepath.Ext(filename) != ".bkp" {
		filename += ".bkp"
	}

	encryptedHex, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	encryptedValue, err := hex.DecodeString(string(encryptedHex))
	if err != nil {
		return "", err
	}

	key := []byte("MMC-GoLang")
	key = append(key, make([]byte, 32-len(key))...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedValue) < nonceSize {
		return "", errors.New("the cipher text is too short")
	}

	nonce, ciphertext := encryptedValue[:nonceSize], encryptedValue[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func prettifyMacAddress(macAddress string) string {
	var result string
	for i, c := range macAddress {
		if i > 0 && i%2 == 0 {
			result += "-"
		}
		result += string(c)
	}
	return strings.ToUpper(result)
}

func changeMacAddress() {
	as, err := getMacAddress()
	if err != nil {
		log.Fatal(err)
	}
	log.Info("MAC Address found. ", "Address", prettifyMacAddress(as[0]))

	// Find the matching network address in registry (Windows grabs the MAC Address from here, so if we change it here, it will change the MAC Address)
	keyPath, err := findMatchingNetworkAddress(as[0])
	if err != nil {
		log.Fatal("Failed to find matching network address. ", "Error", err)
	}
	log.Info("Found registry key path. ", "Path", keyPath)

	_, err = readValueFromFile("original_address")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = saveValueToFile("original_address", as[0])
			if err != nil {
				log.Fatal("Failed to save original MAC Address to file. ", "Error", err)
			}
		} else {
			log.Fatal("Failed to read original MAC Address from file. ", "Error", err)
		}
	} else {
		activeAddress, err := getMacAddress()
		if err != nil {
			log.Fatal(err)
		}
		err = saveValueToFile("previous_address", activeAddress[0])
		if err != nil {
			log.Fatal("Failed to save previous MAC Address to file. ", "Error", err)
		}
	}

	randomMAC, err := generateRandomMAC()
	if err != nil {
		log.Fatal("Failed to generate random MAC Address. ", "Error", err)
	}
	log.Info("Random MAC Address generated. ", "Address", randomMAC)

	if err := setRegistryValue(keyPath, "NetworkAddress", randomMAC); err != nil {
		log.Fatal("Failed to set registry value. ", "Error", err)
	}

	refreshConnection()
}

func restoreMacAddress(macType macType) {
	var filename string
	switch macType {
	case original:
		log.Info("Attemtping to restore original MAC Address")
		filename = "original_address"
	case previous:
		log.Info("Attemtping to restore previous MAC Address")
		filename = "previous_address"
	default:
		log.Fatal("Invalid macType. ", "macType", macType)
	}

	macAddress, err := readValueFromFile(filename)
	if err != nil {
		log.Fatal("Failed to read MAC Address from file. ", "Error", err)
	}
	log.Info("MAC Address read from file. ", "Address", prettifyMacAddress(macAddress))

	activeAddress, err := getMacAddress()
	if err != nil {
		log.Fatal(err)
	}
	keyPath, err := findMatchingNetworkAddress(activeAddress[0])
	if err != nil {
		log.Fatal("Failed to find matching network address. ", "Error", err)
	}
	log.Info("Found registry key path. ", "Path", keyPath)

	if err := setRegistryValue(keyPath, "NetworkAddress", macAddress); err != nil {
		log.Fatal("Failed to set registry value. ", "Error", err)
	}

	refreshConnection()
}

func refreshConnection() {
	log.Info("————————————————————————————————————————————————————————————")
	log.Info("Refreshing network connection")
	log.Info("(You might lose internet for a few seconds)")

	exec.Command("cmd", "/C", "WMIC PATH WIN32_NETWORKADAPTER WHERE PHYSICALADAPTER=TRUE CALL DISABLE >nul 2>&1").Run()
	time.Sleep(time.Second)
	exec.Command("cmd", "/C", "WMIC PATH WIN32_NETWORKADAPTER WHERE PHYSICALADAPTER=TRUE CALL ENABLE >nul 2>&1").Run()
	time.Sleep(time.Second)

	log.Info("Network connection refreshed")
}

func setRegistryValue(keyPath string, valueName string, value string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.WRITE)
	if err != nil {
		return fmt.Errorf("failed to open key: %v", err)
	}
	defer k.Close()

	if err := k.SetStringValue(valueName, value); err != nil {
		return fmt.Errorf("failed to set value: %v", err)
	}

	return nil
}

func generateRandomMAC() (string, error) {
	mac := make([]byte, 6)

	_, err := rand.Read(mac)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Ensure the first byte has the locally administered bit set
	mac[0] = (mac[0] | 0x02) & 0xfe

	// Format the MAC address to fit format used in the registry (no spacers, uppercase)
	return strings.ToUpper(fmt.Sprintf("%02x%02x%02x%02x%02x%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])), nil
}
