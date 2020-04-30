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
	#include <linux/cred.h>

	BPF_PERF_OUTPUT(events);

	struct proc_info_t {
		u32 pid;  				  // PID as in the userspace term (i.e. task->tgid in kernel)
		u32 ppid;				  // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)

		u32 new_uid;
		u32 new_gid;

		char comm[TASK_COMM_LEN]; // 16 bytes
		char function[16]; // name of kprobe (set by text template)
	};

	struct proc_return_info_t {
		u32 pid;				  // PID as in the userspace term (i.e. task->tgid in kernel)
		int ret;                  // return code of traced function
	};

	inline int tracer(struct pt_regs *ctx) {
		
		// get process info
		struct task_struct *task;
		struct proc_info_t procInfo = {};
		task = (struct task_struct *)bpf_get_current_task();
		procInfo.pid = bpf_get_current_pid_tgid() >> 32;
		procInfo.ppid = task->real_parent->tgid;

		struct cred new_creds;
		struct cred* new_creds_ptr;

		bpf_probe_read(&new_creds_ptr, sizeof(new_creds_ptr), &PT_REGS_PARM1(ctx));
		bpf_probe_read(&new_creds, sizeof(new_creds), new_creds_ptr);

		procInfo.new_uid = (u32)new_creds.uid.val;
		procInfo.new_gid = (u32)new_creds.gid.val;

		bpf_get_current_comm(&procInfo.comm, sizeof(procInfo.comm));

		char functionName[] = "{{ .FunctionName }}";
		bpf_probe_read_str(&procInfo.function, 16, &functionName);

		// submit process info
		events.perf_submit(ctx, &procInfo, sizeof(procInfo));

		return 0;
	}

	inline int ret_tracer(struct pt_regs *ctx) {
		struct task_struct *task;
		struct proc_return_info_t procInfo = {};
		task = (struct task_struct *)bpf_get_current_task();
		procInfo.pid = bpf_get_current_pid_tgid() >> 32;
		procInfo.ret = PT_REGS_RC(ctx);
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

func loadProbes(c *config) {

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	runtimeContext, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := range c.EventsToTrace {
		fmt.Println(c.EventsToTrace[i].FunctionName)
		go loadProbesAndListen(runtimeContext, c.EventsToTrace[i])
	}

	<-sig
}

func loadProbesAndListen(ctx context.Context, e event) error {

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

	// err = mod.AttachKretprobe(e.getFunctionName(), kprobeFd, -1)

	table := bcc.NewTable(mod.TableId("events"), mod)
	channel := make(chan []byte)
	lostChannel := make(chan uint64)

	perfMap, err := bcc.InitPerfMap(table, channel, lostChannel)
	if err != nil {
		return err
	}

	perfMap.Start()

listenLoop:
	for {
		select {
		case b := <-channel:
			var p procInfo
			p.unmarshalBinary(b)
			fmt.Printf("%+v\n", p)
		case <-ctx.Done():
			break listenLoop
		}
	}

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
