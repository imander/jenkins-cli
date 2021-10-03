package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/c-bata/go-prompt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
)

var script = `
def sout = new StringBuilder(), serr = new StringBuilder()
def proc = ['/bin/bash', '-c', /%s/].execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(60000)
println "$sout$serr"
`

var credsScript = `
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
      com.cloudbees.plugins.credentials.Credentials.class
)

for (c in creds) {
  println(c.id)
  if (c.properties.description) {
    println("   description: " + c.description)
  }
  if (c.properties.username) {
    println("   username: " + c.username)
  }
  if (c.properties.password) {
    println("   password: " + c.password.getPlainText())
  }
  if (c.properties.passphrase) {
    println("   passphrase: " + c.passphrase.getPlainText())
  }
  if (c.properties.secret) {
    println("   secret: " + c.secret.getPlainText())
  }
  if (c.properties.privateKeySource) {
    println("   privateKey: " + c.getPrivateKey())
  }
  println("")
}
`

var (
	jenkins    = &Context{}
	client     = &http.Client{}
	dirListing = []prompt.Suggest{}
	commands   = []prompt.Suggest{
		{Text: "dump-creds", Description: "Print all stored credentials to the console"},
		{Text: "login", Description: "Log into a Jenkins host"},
		{Text: "exit", Description: "Exit the cli"},
	}
	aliases = map[string]string{
		"l":  "ls",
		"ll": "ls -l",
		"la": "ls -la",
	}
)

type Context struct {
	URL               string
	User              string
	Password          string
	Crumb             string `json:"crumb"`
	CrumbRequestField string `json:"crumbRequestField"`
	Cookies           map[string]*http.Cookie
	CurrentDir        string
	PreviousDir       string
	LoggedIn          bool
}

func main() {
	login()
	p := prompt.New(
		executor,
		completer,
		prompt.OptionLivePrefix(changeLivePrefix),
	)
	p.Run()
}

func login() {
	if err := loginPrompt(); err != nil {
		printError(err.Error())
		return
	}
	fmt.Println()
	if err := getCrumb(); err != nil {
		jenkins.LoggedIn = false
		printError(err.Error())
	} else {
		updateDir("/")
		jenkins.LoggedIn = true
	}
}

func loginPrompt() error {
	u := getInput(urlPrompt(), jenkins.URL)
	ur, err := url.Parse(u)
	if err != nil {
		return errors.Wrap(err, "Invalid URL")
	}
	if !strings.HasPrefix(ur.Scheme, "http") {
		return errors.New("URL must have http/https scheme")
	}
	jenkins.URL = ur.String()
	jenkins.User = getInput(userPrompt(), jenkins.User)
	jenkins.Password = getPassword()
	return nil
}

func getInput(msg, def string) string {
	c := func(in prompt.Document) []prompt.Suggest { return nil }
	in := prompt.Input(msg, c)
	if in == "" {
		return def
	}
	return in
}

func getPassword() string {
	if jenkins.Password != "" {
		fmt.Print("Jenkins password [**********]: ")
	} else {
		fmt.Print("Jenkins password: ")
	}
	pass, _ := terminal.ReadPassword(0)
	p := string(pass)
	if p == "" {
		return jenkins.Password
	}
	return p
}

func urlPrompt() string {
	p := "Jenkins URL"
	if jenkins.URL != "" {
		return p + fmt.Sprintf(" [%s]: ", jenkins.URL)
	}
	return p + ": "
}

func userPrompt() string {
	p := "Jenkins User"
	if jenkins.User != "" {
		return p + fmt.Sprintf(" [%s]: ", jenkins.User)
	}
	return p + ": "
}

func executor(cmd string) {
	if changeDir(cmd) {
		return
	}

	switch cmd {
	case "":
		return
	case "dump-creds":
		scriptConsole(commandPayload(credsScript))
	case "exit":
		os.Exit(0)
	case "login":
		login()
	default:
		scriptConsole(bashPayload(cmd))
	}
}

func completer(in prompt.Document) []prompt.Suggest {
	w := in.GetWordBeforeCursor()
	if in.Text == "" || !strings.Contains(in.Text, " ") {
		return prompt.FilterHasPrefix(commands, w, true)
	}

	return prompt.FilterHasPrefix(dirListing, w, true)
}

func changeLivePrefix() (string, bool) {
	if jenkins.CurrentDir == "" {
		if jenkins.LoggedIn {
			jenkins.CurrentDir = "/"
		} else {
			jenkins.CurrentDir = "jenkins"
		}
	}
	return jenkins.CurrentDir + " >>> ", true
}

func getCrumb() error {
	errMsg := "unable to fetch crumb: %s"
	resp, err := sendRequest(http.MethodGet, jenkins.URL+"/crumbIssuer/api/json", nil)
	if err != nil {
		return fmt.Errorf(errMsg, err.Error())
	}

	err = json.Unmarshal(resp, jenkins)
	if err != nil {
		return fmt.Errorf(errMsg, err.Error())
	}
	return nil
}

func updateCookies(cookies []*http.Cookie) {
	if jenkins.Cookies == nil {
		jenkins.Cookies = map[string]*http.Cookie{}
	}
	for _, cookie := range cookies {
		jenkins.Cookies[cookie.Name] = cookie
	}
}

func sendRequest(method, url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if jenkins.User != "" && jenkins.Password != "" {
		req.SetBasicAuth(jenkins.User, jenkins.Password)
	}
	for k := range jenkins.Cookies {
		req.AddCookie(jenkins.Cookies[k])
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	updateCookies(resp.Cookies())
	return ioutil.ReadAll(resp.Body)
}

func commandPayload(payload string) io.Reader {
	form := url.Values{}
	form.Add("script", payload)
	form.Add(jenkins.CrumbRequestField, jenkins.Crumb)
	return strings.NewReader(form.Encode())
}

func bashPayload(cmd string) io.Reader {
	if alias, ok := aliases[cmd]; ok {
		cmd = alias
	}
	cmd = fmt.Sprintf("cd '%s' && %s", jenkins.CurrentDir, cmd)
	cmd = strings.ReplaceAll(cmd, "/", "\\/")
	return commandPayload(fmt.Sprintf(script, cmd))
}

func scriptConsole(payload io.Reader) {
	if !jenkins.LoggedIn {
		printError("not logged in")
		return
	}
	resp, err := sendRequest(http.MethodPost, jenkins.URL+"/scriptText", payload)
	if err != nil {
		printError(err.Error())
	} else {
		fmt.Print(string(resp))
	}
}

func updateDirListing() {
	dirListing = []prompt.Suggest{}
	list, err := sendRequest(http.MethodPost, jenkins.URL+"/scriptText", bashPayload("ls"))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(list), "\n") {
		dirListing = append(dirListing, prompt.Suggest{Text: line})
	}
}

func checkDir(dir string) string {
	if dir == "/" {
		return "/"
	}
	if !strings.HasPrefix(dir, "/") {
		dir = jenkins.CurrentDir + "/" + dir
	}
	cmd := fmt.Sprintf("[ -d \"%s\" ] && realpath \"%s\" || echo FALSE", dir, dir)
	out, err := sendRequest(http.MethodPost, jenkins.URL+"/scriptText", bashPayload(cmd))
	if err != nil {
		printError(err.Error())
		return jenkins.CurrentDir
	}
	new_dir := strings.TrimSpace(string(out))
	if new_dir == "FALSE" {
		printError("not a directory: %s", dir)
		return jenkins.CurrentDir
	}
	return new_dir
}

func updateDir(dir string) {
	jenkins.PreviousDir = jenkins.CurrentDir
	jenkins.CurrentDir = checkDir(dir)
	if jenkins.PreviousDir != jenkins.CurrentDir {
		go updateDirListing()
	}
}

func changeDir(cmd string) bool {
	dir := ""
	if cmd == "cd" {
		dir = "/"
	} else if strings.HasPrefix(cmd, "cd ") {
		dir = cmd[3:]
	}
	if dir != "" {
		updateDir(dir)
		return true
	}
	return false
}

func printError(msg string, args ...interface{}) {
	msg = "\033[31mError: \033[0m" + msg
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprintf(os.Stderr, msg, args...)
}
