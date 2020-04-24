package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/bcc"
)

const bpfProgram = `
	#include <uapi/linux/ptrace.h>
	#include <linux/sched.h>
	#include <linux/string.h>

	BPF_PERF_OUTPUT(events);

	struct proc_info_t {
		u32 pid;  				  // PID as in the userspace term (i.e. task->tgid in kernel)
		u32 ppid;				  // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
		char comm[TASK_COMM_LEN]; // 16 bytes
		char function[16]; // name of kprobe (set by text template)
	};

	inline int tracer(struct pt_regs *ctx) {
		
		// get process info
		struct task_struct *task;
		struct proc_info_t procInfo = {};
		task = (struct task_struct *)bpf_get_current_task();
		procInfo.pid = bpf_get_current_pid_tgid() >> 32;
		procInfo.ppid = task->real_parent->tgid;
		bpf_get_current_comm(&procInfo.comm, sizeof(procInfo.comm));

		strcpy(procInfo.function, "{{ .FunctionName }}");

		// submit process info
		events.perf_submit(ctx, &procInfo, sizeof(procInfo));

		return 0;
	}
`

func bpfText(e event) (bpfProgramText string) {
	t := template.New("bpf_text")
	t, err := t.Parse(bpfProgram)
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	t.Execute(buf, e)

	return buf.String()
}

func loadProbes(c *config) error {

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	runtimeContext, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := range c.EventsToTrace {
		go loadProbeAndListen(runtimeContext, c.EventsToTrace[i])
	}

	<-sig
	return nil
}

func loadProbeAndListen(ctx context.Context, e event) error {

	bpfProgram := bpfText(e)

	mod := bcc.NewModule(bpfProgram, []string{})
	defer mod.Close()

	kprobeFd, err := mod.LoadKprobe("tracer")
	if err != nil {
		return err
	}

	err = mod.AttachKprobe(e.getFunctionName(), kprobeFd, -1)
	if err != nil {
		return err
	}

	table := bcc.NewTable(mod.TableId("events"), mod)
	channel := make(chan []byte)
	lostChannel := make(chan uint64)

	perfMap, err := bcc.InitPerfMap(table, channel, lostChannel)
	if err != nil {
		return err
	}

	go perfListen(ctx, channel)

	perfMap.Start()
	<-ctx.Done()
	perfMap.Stop()

	return nil
}

func perfListen(ctx context.Context, rawBytes chan []byte) {

	for {
		b := <-rawBytes
		var p procInfo
		p.unmarshalBinary(b)
		fmt.Printf("%+v\n", p)
	}
}
