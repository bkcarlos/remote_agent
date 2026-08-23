package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bkcarlos/remote_agent/internal/credentialstore"
	"github.com/bkcarlos/remote_agent/internal/remoteworker"
)

func main() {
	os.Clearenv()
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "remote-worker: operation failed")
		os.Exit(1)
	}
}

func run(args []string, input io.Reader, output, errorOutput io.Writer) error {
	flags := flag.NewFlagSet("remote-worker", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	encodedPublicKey := flags.String("public-key", "", "Ed25519 verification public key")
	credentialFD := flags.Int("credential-fd", -1, "inherited credential pipe descriptor")
	agentFD := flags.Int("agent-fd", -1, "inherited ssh-agent descriptor")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *credentialFD < 3 {
		return errors.New("invalid worker arguments")
	}
	publicKey, err := base64.RawStdEncoding.Strict().DecodeString(*encodedPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid worker public key")
	}
	credentialFile := os.NewFile(uintptr(*credentialFD), "credential-pipe")
	if credentialFile == nil {
		return errors.New("credential descriptor is unavailable")
	}
	defer credentialFile.Close()
	var agentFile *os.File
	if *agentFD >= 3 {
		agentFile = os.NewFile(uintptr(*agentFD), "ssh-agent")
		if agentFile == nil {
			return errors.New("agent descriptor is unavailable")
		}
		defer agentFile.Close()
	}
	credential, err := credentialstore.ReadWorkerEnvelope(credentialFile, agentFile)
	if err != nil {
		return err
	}
	defer credential.Close()
	if err := remoteworker.ApplyResourceLimits(); err != nil {
		return err
	}
	signedJob, err := io.ReadAll(io.LimitReader(input, remoteworker.MaxSignedBytes+1))
	if err != nil || len(signedJob) > remoteworker.MaxSignedBytes {
		return errors.New("signed job exceeds limit")
	}
	service, err := remoteworker.NewService(ed25519.PublicKey(publicKey), credential, remoteworker.RestrictFilesystem)
	if err != nil {
		return err
	}
	response := service.Execute(context.Background(), signedJob)
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}
