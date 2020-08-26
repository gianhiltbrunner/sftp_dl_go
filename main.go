package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/pkg/sftp"
)

var (
	USER = flag.String("user", os.Getenv("USER"), "ssh username")
	HOST = flag.String("host", "localhost", "ssh server hostname")
	PORT = flag.Int("port", 22, "ssh server port")
	PASS = flag.String("pass", os.Getenv("SOCKSIE_SSH_PASSWORD"), "ssh password")
	SIZE = flag.Int("s", 1<<15, "set max packet size")
)

func init() {
	flag.Parse()
}

func main() {
	var auths []ssh.AuthMethod
	if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))

	}
	if *PASS != "" {
		auths = append(auths, ssh.Password(*PASS))
	}

	config := ssh.ClientConfig{
		User:            *USER,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	addr := fmt.Sprintf("%s:%d", *HOST, *PORT)
	conn, err := ssh.Dial("tcp", addr, &config)
	if err != nil {
		log.Fatalf("unable to connect to [%s]: %v", addr, err)
	}
	defer conn.Close()

	sftp, err := sftp.NewClient(conn)
	if err != nil {
		log.Fatal(err)
	}
	defer sftp.Close()

	//os.Chdir("/")
	var currentDir = "/"
	var oldDir = "" //Dir before download

	for {
		dirRead, err := sftp.ReadDir(currentDir)
		if err != nil {

			//Failed to read dir -> is file
			targetFile := strings.TrimSuffix(currentDir, "/")
			pathSlice := strings.Split(targetFile, "/")
			targetName := pathSlice[len(pathSlice)-1]

			fmt.Println("===" + targetFile + "===")

			go func() {
				srcFile, err := sftp.Open(targetFile)
				if err != nil {
					log.Fatal(err)
				}

				dstFile, err := os.Create("./" + targetName)
				if err != nil {
					log.Fatal(err)
				}
				defer dstFile.Close()

				bytes, err := io.Copy(dstFile, srcFile)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("%d bytes copied\n", bytes)

				err = dstFile.Sync()
				if err != nil {
					log.Fatal(err)
				}
			}()

			currentDir = oldDir

		} else {
			fmt.Println("---" + currentDir + "---")
		}

		for _, element := range dirRead {
			fmt.Println(element.Name())
		}

		reader := bufio.NewReader(os.Stdin)
		pattern, _ := reader.ReadString('\n')
		pattern = strings.TrimSuffix(pattern, "\n")

		globMatches, err := sftp.Glob(currentDir + pattern + "*")
		if err != nil {
			fmt.Println("Failed to glob!")
			log.Fatal(err)
		}

		oldDir = currentDir
		if pattern == ".." {
			splitPattern := strings.Split(currentDir, "/")
			currentDir = strings.Join(splitPattern[:len(splitPattern)-2], "/") + "/"
		} else if len(globMatches) > 0 && pattern != "" {
			currentDir = globMatches[0]
			currentDir = currentDir + "/"
		} else {
			fmt.Println("No match found!")
		}
	}
}
