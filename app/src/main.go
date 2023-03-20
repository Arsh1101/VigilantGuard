package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang gen_execve ./bpf/execve.bpf.c -- -I/usr/include/bpf -I.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

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

func main() {
	setlimit()

	objs := gen_execveObjects{}

	loadGen_execveObjects(&objs, nil)
	// Arsh: I had too pass nil to Tracepoint, I got an error on it.
	link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve, nil)

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("reader err")
	}

	for {
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
			fmt.Printf("On cpu %02d %s ran : %d %s -> user : %d \n", ev.CPU, data.Comm, data.Pid, data.F_name, data.Uid)
		}
	}
}
