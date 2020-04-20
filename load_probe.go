package main

import (
	"bytes"
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

	char function[{{ len .FunctionName }}] = "{{ .FunctionName }}";

	BPF_PERF_OUTPUT(events);

	struct proc_info_t {
		u32 pid;  				  // PID as in the userspace term (i.e. task->tgid in kernel)
		u32 ppid;				  // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
		char comm[TASK_COMM_LEN]; // 16 bytes
		char* function; // name of kprobe (set by text template)
	};

	inline int tracer(struct pt_regs *ctx) {
		
		// get process info
		struct task_struct *task;
		struct proc_info_t procInfo = {};
		task = (struct task_struct *)bpf_get_current_task();
		procInfo.pid = bpf_get_current_pid_tgid() >> 32;
		procInfo.ppid = task->real_parent->tgid;
		bpf_get_current_comm(&procInfo.comm, sizeof(procInfo.comm));
		procInfo.function = function;

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

	for i := range c.EventsToTrace {
		go loadProbeAndListen(c.EventsToTrace[i])
	}

	<-sig
	return nil
}

func loadProbeAndListen(e event) error {

	bpfProgram := bpfText(e)
	fmt.Println(">", bpfProgram)

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

	return nil
}
