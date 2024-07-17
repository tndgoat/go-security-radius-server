package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type Logging struct {
	Status   string `json:"status"`
	UserID   string `json:"userID"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
}

func authentication(username, password string) bool {
	apiURL := "http://35.221.197.240/api/auth/login"
	jsonData := map[string]string{"userName": username, "password": password}
	jsonValue, _ := json.Marshal(jsonData)

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true
	} else {
		return false
	}
}

func parseUsername(username string) (string, string) {
	username = strings.TrimSpace(username)
	parts := strings.Split(username, "@")

	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return parts[0], ""
}

func convertLogging(code radius.Code, userID, domain, password string) string {
	hashedPassword := fmt.Sprintf("%x", sha1.Sum([]byte(password)))
	var status string
	if code == radius.CodeAccessAccept {
		status = "Accept"
	} else {
		status = "Reject"
	}
	logging := Logging{
		Status:   status,
		UserID:   userID,
		Domain:   domain,
		Password: hashedPassword,
	}
	byteArray, err := json.Marshal(logging)
	if err != nil {
		log.Fatal(err)
	}

	return string(byteArray)
}

func logging(logging, filename string) {
	logFilePtr, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s\n", logging)
	currentTime := time.Now()
	formattedTime := currentTime.Format("2006/01/02 15:04:05")
	logFilePtr.WriteString(fmt.Sprintf("%s\t%s\n", formattedTime, logging))
}

func readConfigFile(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		config[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return config, nil
}

func main() {
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		username := strings.TrimSpace(rfc2865.UserName_GetString(r.Packet))
		password := strings.TrimSpace(rfc2865.UserPassword_GetString(r.Packet))

		var code radius.Code
		checkAuth := authentication(username, password)
		userID, domain := parseUsername(username)
		if checkAuth {
			code = radius.CodeAccessAccept
		} else {
			code = radius.CodeAccessReject
		}

		logging(convertLogging(code, userID, domain, password), "log.txt")

		w.Write(r.Response(code))
	}

	configMap, err := readConfigFile("config.ini")
	if err != nil {
		log.Fatal(err)
	}

	port := configMap["server_port"]
	ip := configMap["server_ip"]

	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(handler),
		SecretSource: radius.StaticSecretSource([]byte(`secret`)),
		Addr:         fmt.Sprintf("%s:%s", ip, port),
	}

	log.Printf("Starting server on %s:%s", ip, port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
