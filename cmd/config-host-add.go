/*
 * Minio Client (C) 2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/anaskhan96/soup"
	"github.com/fatih/color"
	"github.com/levigross/grequests"
	"github.com/minio/cli"
	"github.com/minio/mc/pkg/console"
	"github.com/minio/minio-go/pkg/credentials"
	"github.com/minio/minio/pkg/probe"
	"golang.org/x/crypto/ssh/terminal"
)

var configHostAddCmd = cli.Command{
	Name:            "add",
	ShortName:       "a",
	Usage:           "Add a new host to configuration file.",
	Action:          mainConfigHostAdd,
	Before:          setGlobalsFromContext,
	Flags:           globalFlags,
	HideHelpCommand: true,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} ALIAS URL ACCESS-KEY SECRET-KEY [API]

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  1. Add Amazon S3 storage service under "mys3" alias. For security reasons turn off bash history momentarily.
     $ set +o history
     $ {{.HelpName}} mys3 https://s3.amazonaws.com \
                 BKIKJAA5BMMU2RHO6IBB V8f1CwQqAcwo80UEIJEjc5gVQUSSx5ohQ9GSrr12
     $ set -o history

  2. Add Amazon S3 accelerated storage service under "mys3-accel" alias. For security reasons turn off bash history momentarily.
     $ set +o history
     $ {{.HelpName}} mys3-accel https://s3-accelerate.amazonaws.com \
                 BKIKJAA5BMMU2RHO6IBB V8f1CwQqAcwo80UEIJEjc5gVQUSSx5ohQ9GSrr12
     $ set -o history
`,
}

// checkConfigHostAddSyntax - verifies input arguments to 'config host add'.
func checkConfigHostAddSyntax(ctx *cli.Context) {
	if !ctx.Args().Present() {
		return
	}

	args := ctx.Args()
	argsNr := len(args)
	if argsNr < 4 || argsNr > 5 {
		fatalIf(errInvalidArgument().Trace(ctx.Args().Tail()...),
			"Incorrect number of arguments for host add command.")
	}

	signatureAttr{
		alias:     args.Get(0),
		endpoint:  args.Get(1),
		accessKey: args.Get(2),
		secretKey: args.Get(3),
		signType:  args.Get(4),
	}.checkSignatureAttrs()
}

// addHost - add a host config.
func addHost(alias string, hostCfgV8 hostConfigV8) {
	mcCfgV8, err := loadMcConfig()
	fatalIf(err.Trace(globalMCConfigVersion), "Unable to load config `"+mustGetMcConfigPath()+"`.")

	// Add new host.
	mcCfgV8.Hosts[alias] = hostCfgV8

	err = saveMcConfig(mcCfgV8)
	fatalIf(err.Trace(alias), "Unable to update hosts in config version `"+mustGetMcConfigPath()+"`.")

	printMsg(hostMessage{
		op:        "add",
		Alias:     alias,
		URL:       hostCfgV8.URL,
		AccessKey: hostCfgV8.AccessKey,
		SecretKey: hostCfgV8.SecretKey,
		API:       hostCfgV8.API,
	})
}

func getSAMLAssertion(sa samlAttr) (string, *probe.Error) {
	httpSess := grequests.NewSession(nil)

	resp, e := httpSess.Get(sa.idpURL, nil)
	if e != nil {
		return "", probe.NewError(e)
	}

	samlLogin := soup.HTMLParse(resp.String())
	resp.Close()

	payload := extractPayload(samlLogin)
	payload["username"] = sa.username
	payload["password"] = sa.password
	resp, e = httpSess.Post(getURL(resp.RawResponse.Request.URL),
		&grequests.RequestOptions{
			Data:         payload,
			UseCookieJar: true,
		},
	)
	if e != nil {
		return "", probe.NewError(e)
	}

	samlAssertion := soup.HTMLParse(resp.String())
	resp.Close()

	return extractSAMLAssertion(samlAssertion), nil
}

type signatureAttr struct {
	alias     string
	endpoint  string
	accessKey string
	secretKey string
	signType  string
	idpURL    string
}

func (s signatureAttr) checkSignatureAttrs() {
	if !isValidAlias(s.alias) {
		fatalIf(errDummy().Trace(s.alias), "Invalid alias `"+s.alias+"`.")
	}

	if !isValidHostURL(s.endpoint) {
		fatalIf(errDummy().Trace(s.endpoint),
			"Invalid URL `"+s.endpoint+"`.")
	}

	if !isValidAccessKey(s.accessKey) {
		fatalIf(errInvalidArgument().Trace(s.accessKey),
			"Invalid access key `"+s.accessKey+"`.")
	}

	if !isValidSecretKey(s.secretKey) {
		fatalIf(errInvalidArgument().Trace(s.secretKey),
			"Invalid secret key `"+s.secretKey+"`.")
	}

	// Empty value set to default "S3v4".
	if s.signType != "" && !isValidAPI(s.signType) {
		fatalIf(errInvalidArgument().Trace(s.signType),
			"Unrecognized API signature. Valid options are `[S3v4, S3v2]`.")
	}
}

func readSignatureAttr() signatureAttr {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	password := string(bytePassword)
	fmt.Println()

	fmt.Print("SignatureType [S3v4]: ")
	signType, _ := reader.ReadString('\n')
	if strings.TrimSpace(signType) == "" {
		signType = "S3v4"
	}

	fmt.Println()
	return signatureAttr{
		accessKey: strings.TrimSpace(username),
		secretKey: strings.TrimSpace(password),
		signType:  strings.TrimSpace(signType),
	}
}

func mainConfigHostAdd(ctx *cli.Context) error {
	checkConfigHostAddSyntax(ctx)

	console.SetColor("HostMessage", color.New(color.FgGreen))

	args := ctx.Args()
	sa := signatureAttr{
		alias:     args.Get(0),
		endpoint:  args.Get(1),
		accessKey: args.Get(2),
		secretKey: args.Get(3),
	}
	signType := args.Get(4)
	if signType == "" {
		signType = "S3v4"
	}
	sa.signType = signType

	if !args.Present() {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("AuthType [regular]: ")
		authType, _ := reader.ReadString('\n')

		fmt.Print("Alias: ")
		alias, _ := reader.ReadString('\n')
		alias = strings.TrimSpace(alias)

		fmt.Print("Endpoint: ")
		endpoint, _ := reader.ReadString('\n')
		endpoint = strings.TrimSpace(endpoint)

		if strings.TrimSpace(authType) == "saml" {
			credsValue, idpURL, err := getSTSCreds(endpoint)
			fatalIf(err.Trace(endpoint), "Unable to fetch sts credentials")
			sa = signatureAttr{
				alias:     alias,
				endpoint:  endpoint,
				accessKey: credsValue.AccessKeyID,
				secretKey: credsValue.SecretAccessKey,
				signType:  credentials.SignatureV4.String(), // Signature v4 is default signer for all rolling access keys.
				idpURL:    idpURL,
			}
		} else {
			sa = readSignatureAttr()
			sa.alias = alias
			sa.endpoint = endpoint
			sa.checkSignatureAttrs()
		}
	}

	hostCfg := hostConfigV8{
		URL:       sa.endpoint,
		AccessKey: sa.accessKey,
		SecretKey: sa.secretKey,
		API:       sa.signType,
		IdpURL:    sa.idpURL,
	}

	addHost(sa.alias, hostCfg) // Add a host with specified credentials.
	return nil
}
