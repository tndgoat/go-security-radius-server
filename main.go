package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type User struct {
	Username string
	Password string
}

type Logging struct {
	Status   string `json:"status"`
	UserID   string `json:"userID"`
	Company  string `json:"company"`
	Password string `json:"password"`
}

func authentication(username, password string, userList []User) bool {
	for _, user := range userList {
		if user.Username == username && user.Password == password {
			return true
		}
	}
	return false
}

func parseUsername(username string) (string, string) {
	username = strings.TrimSpace(username)
	parts := strings.Split(username, "@")

	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return parts[0], ""
}

func convertLogging(code radius.Code, userID, company, password string) string {
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
		Company:  company,
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
	defer file.Close() // đóng file sau khi hàm kết thúc

	config := make(map[string]string) // khởi tạo map
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, "=", 2) // tách thành mảng có tối đa 2 phân tử phân cách bởi dấu "="
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
	userList := []User{
		User{"tungnd@hcmut.edu.vn", "hoidai"},
		User{"hoangvo@hcmut.edu.vn", "thuky"},
		User{"tuannda@hcmut.edu.vn", "captain"},
	}

	handler := func(w radius.ResponseWriter, r *radius.Request) {
		username := strings.TrimSpace(rfc2865.UserName_GetString(r.Packet))
		password := strings.TrimSpace(rfc2865.UserPassword_GetString(r.Packet))

		var code radius.Code
		checkAuth := authentication(username, password, userList)
		userID, company := parseUsername(username)
		if checkAuth == true {
			code = radius.CodeAccessAccept
		} else {
			code = radius.CodeAccessReject
		}

		logging(convertLogging(code, userID, company, password), "log.txt")

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
