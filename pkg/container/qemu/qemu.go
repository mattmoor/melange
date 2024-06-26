// Copyright 2024 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package qemu

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/ssh"

	apko_build "chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"
	apko_types "chainguard.dev/apko/pkg/build/types"
	mcontainer "chainguard.dev/melange/pkg/container"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/u-root/u-root/pkg/cpio"
)

var _ mcontainer.Debugger = (*qemu)(nil)

const (
	QEMUName = "qemu"
)

// qemu is a Runner implementation that uses the qemu library.
type qemu struct {
	cmd *exec.Cmd
	w   io.WriteCloser

	sshClient *ssh.Client

	port   int
	client ed25519.PrivateKey
	server ed25519.PrivateKey
}

// NewRunner returns a QEMU Runner implementation.
func NewRunner(ctx context.Context) (mcontainer.Runner, error) {
	_, clientPrivKey, err := ed25519.GenerateKey(nil) // NB: If rand is nil, crypto/rand.Reader will be used
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}
	_, serverPrivKey, err := ed25519.GenerateKey(nil) // NB: If rand is nil, crypto/rand.Reader will be used
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}

	return &qemu{
		port:   1234,
		client: clientPrivKey,
		server: serverPrivKey,
	}, nil
}

func (qvm *qemu) Name() string {
	return QEMUName
}

func (qvm *qemu) Close() error {
	if qvm.sshClient != nil {
		return qvm.sshClient.Close()
	}
	return nil
}

// StartPod starts a pod for supporting a QEMU task, if
// necessary.
func (qvm *qemu) StartPod(ctx context.Context, cfg *mcontainer.Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "qemu.StartPod")
	defer span.End()

	// TODO: Start up the qemu process and squirrel away the STDIN to
	// pass commands.

	cpu := cfg.CPU
	if cpu == "" {
		cpu = "host"
	}
	mem := cfg.Memory
	if mem == "" {
		mem = "10000"
	}

	clog.InfoContextf(ctx, "starting qemu with config from: %s", cfg.ImgRef)

	// qemu-system-{arch}
	baseargs := []string{
		// -kernel /tmp/vmlinuz
		"-kernel", os.Getenv("MELANGE_KERNEL"),
		// -initrd /tmp/initramfs.cpio
		"-initrd", filepath.Join(cfg.ImgRef, "initramfs.cpio"),
		// -m 1000
		"-m", mem,
		// -cpu host
		"-cpu", cpu,
		// -nographic
		"-nographic",
		// -machine virt
		"-machine", "virt",
		// silence the systemd output.
		"-append", "quiet",
		// port-forward ssh to the host.
		"-netdev", fmt.Sprintf("user,id=vnet,hostfwd=tcp::%d-:22", qvm.port),
		"-device", "virtio-net-pci,netdev=vnet",
		// Mount the workspace
		"-virtfs", fmt.Sprintf("local,path=%s,mount_tag=workspace,security_model=none,id=workspace", cfg.WorkspaceDir),
	}

	switch runtime.GOOS {
	case "darwin":
		baseargs = append(baseargs, "-accel", "hvf")
	case "linux":
		baseargs = append(baseargs, "-enable-kvm")
	}

	binary := fmt.Sprintf("qemu-system-%s", cfg.Arch.ToAPK())
	qvm.cmd = exec.CommandContext(ctx, binary, baseargs...)

	clog.FromContext(ctx).Infof("executing: %s", strings.Join(qvm.cmd.Args, " "))

	// qvm.cmd.Stdout = os.Stdout
	// qvm.cmd.Stderr = os.Stderr
	qvm.cmd.Stdin, qvm.w = io.Pipe()

	if err := qvm.cmd.Start(); err != nil {
		return err
	}

	signer, err := ssh.NewSignerFromKey(qvm.client)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}
	hostPublicKey, err := ssh.NewPublicKey(qvm.server.Public())
	if err != nil {
		return fmt.Errorf("failed to generate host public key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.FixedHostKey(hostPublicKey),
		Timeout:         10 * time.Second,
	}

	for {
		// Dial your ssh server.
		conn, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", qvm.port), config)
		if err == nil {
			qvm.sshClient = conn
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
			clog.DebugContextf(ctx, "waiting for qemu to start: %v", err)
			continue
		}
	}

	// Mount the workspace
	return qvm.Run(ctx, nil, nil, "mount", "-t", "9p", "-o", "trans=virtio", "workspace", "/home/build", "-oversion=9p2000.L")
}

// TerminatePod terminates a pod for supporting a QEMU task,
// if necessary.
func (qvm *qemu) TerminatePod(ctx context.Context, cfg *mcontainer.Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "qemu.TerminatePod")
	defer span.End()

	clog.InfoContext(ctx, "powering off VM")

	qvm.w.Write([]byte("poweroff\n"))
	qvm.w.Close()
	return qvm.cmd.Wait()
}

// TestUsability determines if the QEMU runner can be used
// as a container runner.
func (qvm *qemu) TestUsability(ctx context.Context) bool {
	arch := types.Architecture(runtime.GOARCH)
	if _, err := exec.LookPath(fmt.Sprintf("qemu-system-%s", arch.ToAPK())); err != nil {
		clog.InfoContextf(ctx, "qemu-system-%s not found on PATH", arch.ToAPK())
		return false
	}

	if _, ok := os.LookupEnv("MELANGE_KERNEL"); !ok {
		clog.InfoContext(ctx, "MELANGE_KERNEL not set")
		return false
	}
	return true
}

// OCIImageLoader create a loader to load an OCI image into the QEMU daemon.
func (qvm *qemu) OCIImageLoader() mcontainer.Loader {
	return &qemuOCILoader{
		client: qvm.client.Public(),
		server: qvm.server,
	}
}

// TempDir returns the base for temporary directory. For qemu
// this is whatever the system provides.
func (qvm *qemu) TempDir() string {
	return ""
}

// Run runs a qemu task given a Config and command string.
// The resultant filesystem can be read from the io.ReadCloser
func (qvm *qemu) Run(ctx context.Context, _ *mcontainer.Config, env map[string]string, args ...string) error {
	clog.InfoContextf(ctx, "running command %s", strings.Join(args, " "))

	session, err := qvm.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// TODO(mattmoor): Figure out why this doesn't work.
	// for k, v := range env {
	// 	if err := session.Setenv(k, v); err != nil {
	// 		return fmt.Errorf("failed to set env var %s: %w", k, err)
	// 	}
	// }

	// It looks like "set -e" is not the default, so things don't fail as we
	// expect them to.
	return session.Run("set -e;" + strings.Join(args, " "))
}

func (qvm *qemu) Debug(ctx context.Context, cfg *mcontainer.Config, env map[string]string, args ...string) error {
	clog.InfoContextf(ctx, "debugging command %s", strings.Join(args, " "))

	session, err := qvm.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// TODO(mattmoor): Figure out why this doesn't work.
	// for k, v := range env {
	// 	if err := session.Setenv(k, v); err != nil {
	// 		return fmt.Errorf("failed to set env var %s: %w", k, err)
	// 	}
	// }

	// It looks like "set -e" is not the default, so things don't fail as we
	// expect them to.
	return session.Run("set -e;" + strings.Join(args, " "))
}

// WorkspaceTar implements Runner
// This is a noop for qemu, which uses bind-mounts to manage the workspace
func (qvm *qemu) WorkspaceTar(ctx context.Context, cfg *mcontainer.Config) (io.ReadCloser, error) {
	return nil, nil
}

type qemuOCILoader struct {
	client crypto.PublicKey
	server ed25519.PrivateKey
}

func (b qemuOCILoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (ref string, err error) {
	_, span := otel.Tracer("melange").Start(ctx, "qemu.LoadImage")
	defer span.End()

	clog.InfoContext(ctx, "loading image layer")

	u, err := layer.Uncompressed()
	if err != nil {
		return "", err
	}
	defer u.Close()

	tarReader := tar.NewReader(u)

	tmpdir, err := os.MkdirTemp("", "melange-qemu-*")
	if err != nil {
		return "", err
	}

	tmp, err := os.Create(filepath.Join(tmpdir, "initramfs.cpio"))
	if err != nil {
		return "", err
	}
	defer tmp.Close()

	w := cpio.NewDedupWriter(cpio.Newc.Writer(tmp))

	// Iterate through the tar archive entries
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			fmt.Println("Error reading tar entry:", err)
			return "", err
		}

		// Determine CPIO file mode based on TAR typeflag
		switch header.Typeflag {
		case tar.TypeDir:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.Directory(header.Name, uint64(header.Mode)),
			}); err != nil {
				return "", err
			}

		case tar.TypeSymlink:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.Symlink(header.Name, header.Linkname),
			}); err != nil {
				return "", err
			}

		case tar.TypeReg:
			var original bytes.Buffer
			// TODO(mattmoor): Do something better here, but unfortunately the
			// cpio stuff wants a seekable reader, so coming from a tar reader
			// I'm not sure how much leeway we have to do something better
			// than buffering.
			//nolint:gosec
			if _, err := io.Copy(&original, tarReader); err != nil {
				fmt.Println("Error reading file content:", err)
				return "", err
			}

			var content *bytes.Buffer

			// Copy unmodified files directly
			switch header.Name {

			// Boot straight to busybox shell as root (like a container!)
			case "usr/lib/systemd/system/serial-getty@.service":
				// Modify the target file
				content = bytes.NewBufferString(strings.ReplaceAll(
					original.String(),
					"ExecStart=",
					"ExecStart=-/bin/sh -l \n#",
				))

			// Disable systemd login; boot straight to busybox shell as root (like a container!)
			case "usr/lib/systemd/system/systemd-vconsole-setup.service":
				// Modify the target file
				content = bytes.NewBufferString(strings.ReplaceAll(
					original.String(),
					"ExecStart=",
					"ExecStart=/bin/true \n#",
				))

			// Enable pubkey login
			case "etc/ssh/sshd_config":
				// Modify the target file
				content = bytes.NewBufferString(strings.ReplaceAll(
					original.String(),
					"#PubkeyAuthentication",
					"PubkeyAuthentication",
				))

			default:
				content = &original
			}

			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.StaticFile(header.Name, content.String(), uint64(header.Mode)),
			}); err != nil {
				return "", err
			}

		case tar.TypeChar:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.CharDev(header.Name, uint64(header.Mode), uint64(header.Devmajor), uint64(header.Devminor)),
			}); err != nil {
				return "", err
			}

		default:
			fmt.Printf("Unsupported TAR typeflag: %c for %s\n", header.Typeflag, header.Name)
			continue // Skip unsupported types
		}
	}

	// Add a network configuration file
	if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
		cpio.StaticFile("etc/systemd/network/20-wired.network", `[Match]
Name=en*
[Network]
DHCP=yes
`, 0o777)}); err != nil {
		return "", err
	}

	publicKey, err := ssh.NewPublicKey(b.client)
	if err != nil {
		return "", fmt.Errorf("failed to generate public key: %w", err)
	}
	publicKeyString := "ssh-ed25519" + " " + base64.StdEncoding.EncodeToString(publicKey.Marshal())

	if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
		cpio.StaticFile("root/.ssh/authorized_keys", publicKeyString, 0o600)}); err != nil {
		return "", fmt.Errorf("failed to write authorized_keys file: %w", err)
	}

	// Create a new _host_ SSH key pair for the server
	// We need to do this because the apk package for openssh-server has a
	// scriptlet that generates the host keys, and that doesn't get executed
	// when apko installs it. So, just generate the ed25529 key pair here.
	hostP, err := ssh.MarshalPrivateKey(b.server, "")
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	hostPrivateKeyPem := pem.EncodeToMemory(hostP)
	hostPrivateKeyString := string(hostPrivateKeyPem)
	hostPublicKey, err := ssh.NewPublicKey(b.server.Public())
	if err != nil {
		return "", fmt.Errorf("failed to generate host public key: %w", err)
	}
	hostPublicKeyString := "ssh-ed25519" + " " + base64.StdEncoding.EncodeToString(hostPublicKey.Marshal())

	if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
		cpio.StaticFile("etc/ssh/ssh_host_ed25519_key.pub", hostPublicKeyString, 0o644)}); err != nil {
		return "", fmt.Errorf("failed to write host pub key file: %w", err)
	}
	if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
		cpio.StaticFile("etc/ssh/ssh_host_ed25519_key", hostPrivateKeyString, 0o600)}); err != nil {
		return "", fmt.Errorf("failed to write host private key file: %w", err)
	}

	// Add sshd service file
	// Note the hack in ExecStart to make sure the /root/.ssh directory is
	// created with the correct permissions before starting sshd.
	if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
		cpio.StaticFile("usr/lib/systemd/system/sshd.service", `[Unit]
Description=OpenSSH server daemon
After=syslog.target network.target auditd.service
[Service]
ExecStartPre=/bin/chmod 700 /root/.ssh
ExecStart=/usr/sbin/sshd -E /tmp/sshd.log -D
[Install]
WantedBy=multi-user.target
`, 0o777)}); err != nil {
		return "", err
	}

	w.WriteRecord(cpio.TrailerRecord)

	return tmpdir, nil
}

func (b qemuOCILoader) RemoveImage(ctx context.Context, ref string) error {
	clog.FromContext(ctx).Infof("removing image path %s", ref)
	return os.RemoveAll(ref)
}
