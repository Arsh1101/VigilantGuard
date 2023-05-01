package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang gen_execve ./bpf/execve.bpf.c -- -I/usr/include/bpf -I.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	comunication "gobpf-test/src/communications"
)

var wg sync.WaitGroup

type exec_data_t struct {
	Pid uint32
	//Arsh: get uid
	Uid    uint32
	F_name [32]byte
	Comm   [32]byte
}

func setlimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}
}

// Privilege Escalation SIGMA Rule
func createSRule_PE(content string) string {
	result := `title: Privileged User Has Been Created
id: ` + uuid.New().String() + `
description: Detects the addition of a new user to a privileged group such as "root" or "sudo"
references:
- https://digital.nhs.uk/cyber-alerts/2018/cc-2825
- https://linux.die.net/man/8/useradd
- https://github.com/redcanaryco/atomic-red-team/blob/25acadc0b43a07125a8a5b599b28bbc1a91ffb06/atomics/T1136.001/T1136.001.md#atomic-test-5---create-a-new-user-in-linux-with-root-uid-and-gid
author: Pawel Mazur
date: ` + time.Now().Format("2006-01-02") + `
tags:
- attack.persistence
- attack.t1136.001
- attack.t1098
logsource:
- product: linux
- definition: '/var/log/secure on REHL systems or /var/log/auth.log on debian like Systems needs to be collected in order for this detection to work'
- detection: ` + content + `
falsepositives:
- Administrative activity
status: experimental
level: high`
	return result
}

func createLogFile(filename string, content string) error {

	// Check if the log directory exists
	const defaultLogDir string = "/var/log/vigilant-guard"
	_, err := os.Stat(defaultLogDir)
	if os.IsNotExist(err) {
		fmt.Println("Hi")
		// Create the log directory if it doesn't exist
		err = os.Mkdir(defaultLogDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create log directory: %s", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check log directory: %s", err)
	}
	// Create the log file
	f, err := os.Create(fmt.Sprintf(defaultLogDir+"/%s", filename))
	if err != nil {
		return fmt.Errorf("failed to create log file: %s", err)
	}
	defer f.Close()

	// Write content to the log file
	_, err = f.WriteString(content)
	if err != nil {
		return fmt.Errorf("failed to write to log file: %s", err)
	}

	return nil
}

func logWorker(info string) {
	defer wg.Done()
	postFileName := strings.ReplaceAll(time.Now().String(), " ", "_")
	postFileName = strings.ReplaceAll(postFileName, ":", "_")
	createLogFile("lnx_privileged_user_creation_"+postFileName+".yaml", createSRule_PE(info))
	// time.Sleep(5 * time.Second)
}

func main() {
	//
	setlimit()

	objs := gen_execveObjects{}

	loadGen_execveObjects(&objs, nil)
	// Arsh: I had too pass nil to Tracepoint, I got an error on it.
	link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve, nil)

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("reader err")
	}

	startTimeLog, _ := time.Parse(time.RFC3339, "2022-11-26T07:04:05Z")

	for {
		// Arsh: It should work on background
		//
		go func() {
			startTimeLog = comunication.TransferLogs(startTimeLog)
		}()
		ev, err := rd.Read()
		if err != nil {
			log.Fatalf("Read fail")
		}

		if ev.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", ev.LostSamples)
			continue
		}

		b_arr := bytes.NewBuffer(ev.RawSample)

		var data exec_data_t
		if err := binary.Read(b_arr, binary.LittleEndian, &data); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}
		//Arsh: get uid
		// fmt.Printf("On cpu %02d %s ran : %d %s -> user : %d \n",
		// 	ev.CPU, data.Comm, data.Pid, data.F_name, data.Uid)

		//Arsh: test the danger of the root running somthing on machine.
		if data.Uid == 0 {
			// fmt.Printf("On cpu %02d %s ran : %d %s -> user : %d \n", ev.CPU, data.Comm, data.Pid, data.F_name, data.Uid)
			temp := fmt.Sprintf("On cpu %02d %s ran - %d %s -> user - %d", ev.CPU, string(bytes.Trim(data.Comm[:], "\x00")), data.Pid, string(bytes.Trim(data.F_name[:], "\x00")), data.Uid)
			wg.Add(1)
			// fmt.Println(temp)
			go logWorker(temp)
		}
	}
	//Arsh: check before colse interrupt
	wg.Wait()
}
