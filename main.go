package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/moby/moby/client"
)

const URL = "https://vulners.com/api/v3/audit/audit/"

var (
	OSVersion      = []string{"cat", "/etc/os-release"}
	UbuntuPackages = []string{"dpkg-query", "-W", "-f=${Package} ${Version} ${Architecture}\n"}
	CentOSPackages = []string{"rpm", "-qa"}
	AlpinePackages = []string{"apk", "-v", "info"}
	UbuntuOS       = []string{"debian", "ubuntu", "kali"}
	CentOS         = []string{"rhel", "centos", "oraclelinux", "suse", "fedora"}
	AlpineOS       = []string{"alpine"}
)

// RequestBody describe JSON for request
type RequestBody struct {
	Os      string   `json:"os"`
	Version string   `json:"version"`
	Package []string `json:"package"`
}

// ResponseBody contains response from vulners.com
type ResponseBody struct {
	Result string `json:"result"`
	Data   struct {
		Error           string   `json:"error"`
		ErrorCode       int      `json:"errorCode"`
		Vulnerabilities []string `json:"vulnerabilities"`
		Reasons         []struct {
			Package         string `json:"package"`
			ProvidedVersion string `json:"providedVersion"`
			BulletinVersion string `json:"bulletinVersion"`
			ProvidedPackage string `json:"providedPackage"`
			BulletinPackage string `json:"bulletinPackage"`
			Operator        string `json:"operator"`
			BulletinID      string `json:"bulletinID"`
		} `json:"reasons"`
		Cvss struct {
			Score  float64 `json:"score"`
			Vector string  `json:"vector"`
		} `json:"cvss"`
		Cvelist []string `json:"cvelist"`
		ID      string   `json:"id"`
	} `json:"data"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	ctx := context.Background()

	cli, err := client.NewEnvClient()
	if err != nil {
		log.Fatal(err)
	}

	resp, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range resp {
		getInfo(cli, ctx, v)
	}
}

func getInfo(cli *client.Client, ctx context.Context, container types.Container) {
	fmt.Println("For container with ID:", container.ID)
	osver := executeCmd(cli, ctx, container.ID, OSVersion)

	var pkgs []string
	if checkOS(osver, UbuntuOS) {
		temp := executeCmd(cli, ctx, container.ID, UbuntuPackages)
		pkgs = strings.Split(temp, "\r\n")
	} else if checkOS(osver, CentOS) {
		temp := executeCmd(cli, ctx, container.ID, CentOSPackages)
		pkgs = strings.Split(temp, "\r\n")
	} else if checkOS(osver, AlpineOS) {
		temp := executeCmd(cli, ctx, container.ID, AlpinePackages)
		temp2 := strings.Split(temp, "\r\n")
		for _, v := range temp2 {
			if !strings.Contains(v, "WARNING") {
				pkgs = append(pkgs, v)
			}
		}
	} else {
		log.Fatal("Can't determine type of OS or OS is not supported: ", osver)
	}

	name, ver := getOSNameAndVersion(osver)
	fmt.Println("OS:", name+" "+ver)
	body := &RequestBody{
		Os:      name,
		Version: ver,
		Package: pkgs,
	}
	_, err := getVulnerabilities(body)
	if err != nil {
		log.Fatal(err)
	}
}

func checkOS(text string, options []string) bool {
	var res bool
	for _, v := range options {
		if strings.Contains(strings.ToLower(text), v) {
			res = true
			break
		}
	}
	return res
}

func getOSNameAndVersion(text string) (string, string) {
	var name string
	var version string

	if i := strings.Index(text, "ID="); i > -1 {
		name = assign(text[i+3:])
	}
	if i := strings.Index(text, "VERSION_ID="); i > -1 {
		version = assign(text[i+11:])
	}

	return name, version
}

func assign(text string) string {
	var res string
	if string(text[0]) == "\"" {
		i := strings.Index(text[1:], "\"")
		res = text[1 : i+1]
	} else {
		i := strings.Index(text, "\r")
		res = text[:i]
	}
	return res
}

func executeCmd(cli *client.Client, ctx context.Context, ID string, cmd []string) string {
	params := types.ExecConfig{
		AttachStderr: true,
		AttachStdout: true,
		Tty:          true,
		Cmd:          cmd,
	}

	resp, err := cli.ContainerExecCreate(ctx, ID, params)
	if err != nil {
		log.Fatal(err)
	}

	hijack, err := cli.ContainerExecAttach(ctx, resp.ID, params)
	if err != nil {
		log.Fatal(err)
	}
	defer hijack.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(hijack.Reader)
	return buf.String()
}

func getVulnerabilities(rb *RequestBody) ([]string, error) {
	client := http.Client{
		Timeout: 30 * time.Second,
	}

	data, err := json.Marshal(rb)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, URL, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}()

	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	body := &ResponseBody{}
	err = json.Unmarshal(data, body)
	if err != nil {
		return nil, err
	}

	return extractVulnerabilitiesFromResponse(body), nil
}

func extractVulnerabilitiesFromResponse(body *ResponseBody) []string {
	var result []string

	if body.Result != "OK" {
		log.Println("Vulners err0r:", body.Data.Error)
	} else {
		if len(body.Data.Cvelist) > 0 || len(body.Data.Reasons) > 0 {
			fmt.Println("Achtung! Vulnerabilities were found!")
			if len(body.Data.Cvelist) > 0 {
				fmt.Println("List of CVE:")
				for _, v := range body.Data.Cvelist {
					fmt.Println(v)
				}
			}
			if len(body.Data.Reasons) > 0 {
				fmt.Println("List of Bulletin ID:")
				for _, v := range body.Data.Reasons {
					fmt.Println(v.BulletinID)
				}
			}
		} else {
			fmt.Println("Container is clean, congratulations!")
		}
	}

	return result
}
