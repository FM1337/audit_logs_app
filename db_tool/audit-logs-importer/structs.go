package main

// rwcut is our rwcut output structure for inserting into the database
type rwcut struct {
	ID              string
	SourceIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
	Protocol        int
	Packets         int
	Bytes           int
	Flags           string
	StartTime       string
	Duration        float64
	EndTime         string
	Sensor          string
	Hash            string
}

type linuxLog struct {
	ID       string
	Type     string
	DateTime string
	Data     interface{}
	Hash     string
}

type windowsLog struct {
	ID              string `csv:"-"`
	Keywords        string `csv:"Keywords"`
	DateTime        string `csv:"Date and Time"`
	Source          string `csv:"Source"`
	EventID         int    `csv:"Event ID"`
	TaskCategory    string `csv:"Task Category"`
	TaskDescription string `csv:"Task Description"`
	Hash            string `csv:"-"`
}
type Avc []struct {
	Data struct {
		Avc []struct {
			Apparmor  []string `json:"apparmor"`
			Comm      []string `json:"comm"`
			Name      []string `json:"name"`
			Operation []string `json:"operation"`
			Pid       []string `json:"pid"`
			Profile   []string `json:"profile"`
		} `json:"avc"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type BprmFcaps []struct {
	Data struct {
		BprmFcaps struct {
			Fe    []string `json:"fe"`
			Fi    []string `json:"fi"`
			Fp    []string `json:"fp"`
			Fver  []string `json:"fver"`
			OldPa []string `json:"old_pa"`
			OldPe []string `json:"old_pe"`
			OldPi []string `json:"old_pi"`
			OldPp []string `json:"old_pp"`
			Pa    []string `json:"pa"`
			Pe    []string `json:"pe"`
			Pi    []string `json:"pi"`
			Pp    []string `json:"pp"`
		} `json:"bprm_fcaps"`
	} `json:"data"`
	Error  string   `json:"error"`
	Serial int64    `json:"serial"`
	Text   []string `json:"text"`
	Time   string   `json:"time"`
}

type ConfigChange []struct {
	Data struct {
		ConfigChange struct {
			AuditBacklogLimit []string `json:"audit_backlog_limit"`
			AuditFailure      []string `json:"audit_failure"`
			Auid              []string `json:"auid"`
			Key               []string `json:"key"`
			List              []string `json:"list"`
			Old               []string `json:"old"`
			Op                []string `json:"op"`
			Res               []string `json:"res"`
			Ses               []string `json:"ses"`
		} `json:"config_change"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type CredAcq []struct {
	Data struct {
		CredAcq struct {
			Acct     []string `json:"acct"`
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Exe      []string `json:"exe"`
			Grantors []string `json:"grantors"`
			Hostname []string `json:"hostname"`
			Op       []string `json:"op"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
		} `json:"cred_acq"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type CredDisp []struct {
	Data struct {
		CredDisp struct {
			Acct     []string `json:"acct"`
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Exe      []string `json:"exe"`
			Grantors []string `json:"grantors"`
			Hostname []string `json:"hostname"`
			Op       []string `json:"op"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
		} `json:"cred_disp"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type CredRefr []struct {
	Data struct {
		CredRefr struct {
			Acct     []string `json:"acct"`
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Exe      []string `json:"exe"`
			Grantors []string `json:"grantors"`
			Hostname []string `json:"hostname"`
			Op       []string `json:"op"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
		} `json:"cred_refr"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type DaemonStart []struct {
	Data struct {
		DaemonStart struct {
			Auid   []string `json:"auid"`
			Format []string `json:"format"`
			Kernel []string `json:"kernel"`
			Op     []string `json:"op"`
			Pid    []string `json:"pid"`
			Res    []string `json:"res"`
			Ses    []string `json:"ses"`
			Subj   []string `json:"subj"`
			UID    []string `json:"uid"`
			Ver    []string `json:"ver"`
		} `json:"daemon_start"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type Execve []struct {
	Data struct {
		Execve []string `json:"execve"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type Login []struct {
	Data struct {
		Login struct {
			Auid    []string `json:"auid"`
			OldAuid []string `json:"old-auid"`
			OldSes  []string `json:"old-ses"`
			Pid     []string `json:"pid"`
			Res     []string `json:"res"`
			Ses     []string `json:"ses"`
			Tty     []string `json:"tty"`
			UID     []string `json:"uid"`
		} `json:"login"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type Path []struct {
	Data struct {
		Path []struct {
			CapFe    []string `json:"cap_fe"`
			CapFi    []string `json:"cap_fi"`
			CapFp    []string `json:"cap_fp"`
			CapFver  []string `json:"cap_fver"`
			Dev      []string `json:"dev"`
			Inode    []string `json:"inode"`
			Mode     []string `json:"mode"`
			Name     []string `json:"name"`
			Nametype []string `json:"nametype"`
			Ogid     []string `json:"ogid"`
			Ouid     []string `json:"ouid"`
			Rdev     []string `json:"rdev"`
		} `json:"path"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type Proctitle []struct {
	Data struct {
		Proctitle struct {
			Proctitle []string `json:"proctitle"`
		} `json:"proctitle"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type ServiceStart []struct {
	Data struct {
		ServiceStart struct {
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Comm     []string `json:"comm"`
			Exe      []string `json:"exe"`
			Hostname []string `json:"hostname"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
			Unit     []string `json:"unit"`
		} `json:"service_start"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type ServiceStop []struct {
	Data struct {
		ServiceStop struct {
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Comm     []string `json:"comm"`
			Exe      []string `json:"exe"`
			Hostname []string `json:"hostname"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
			Unit     []string `json:"unit"`
		} `json:"service_stop"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type Syscall []struct {
	Data struct {
		Syscall struct {
			A0      []string `json:"a0"`
			A1      []string `json:"a1"`
			A2      []string `json:"a2"`
			A3      []string `json:"a3"`
			Arch    []string `json:"arch"`
			Auid    []string `json:"auid"`
			Comm    []string `json:"comm"`
			Egid    []string `json:"egid"`
			Euid    []string `json:"euid"`
			Exe     []string `json:"exe"`
			Exit    []string `json:"exit"`
			Fsgid   []string `json:"fsgid"`
			Fsuid   []string `json:"fsuid"`
			Gid     []string `json:"gid"`
			Items   []string `json:"items"`
			Key     []string `json:"key"`
			Pid     []string `json:"pid"`
			Ppid    []string `json:"ppid"`
			Ses     []string `json:"ses"`
			Sgid    []string `json:"sgid"`
			Success []string `json:"success"`
			Suid    []string `json:"suid"`
			Syscall []string `json:"syscall"`
			Tty     []string `json:"tty"`
			UID     []string `json:"uid"`
		} `json:"syscall"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type SystemBoot []struct {
	Data struct {
		SystemBoot struct {
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Comm     []string `json:"comm"`
			Exe      []string `json:"exe"`
			Hostname []string `json:"hostname"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
		} `json:"system_boot"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type SystemRunlevel []struct {
	Data struct {
		SystemRunlevel struct {
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Comm     []string `json:"comm"`
			Exe      []string `json:"exe"`
			Hostname []string `json:"hostname"`
			Newlevel []string `json:"new-level"`
			Oldlevel []string `json:"old-level"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
		} `json:"system_runlevel"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type UserAcct []struct {
	Data struct {
		UserAcct struct {
			Acct     []string `json:"acct"`
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Exe      []string `json:"exe"`
			Grantors []string `json:"grantors"`
			Hostname []string `json:"hostname"`
			Op       []string `json:"op"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
		} `json:"user_acct"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type UserAuth []struct {
	Data struct {
		UserAuth struct {
			Acct     []string `json:"acct"`
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Exe      []string `json:"exe"`
			Grantors []string `json:"grantors"`
			Hostname []string `json:"hostname"`
			Op       []string `json:"op"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
		} `json:"user_auth"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type UserCmd []struct {
	Data struct {
		UserCmd struct {
			Auid     []string `json:"auid"`
			Cmd      []string `json:"cmd"`
			Cwd      []string `json:"cwd"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
		} `json:"user_cmd"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type UserEnd []struct {
	Data struct {
		UserEnd struct {
			Acct     []string `json:"acct"`
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Exe      []string `json:"exe"`
			Grantors []string `json:"grantors"`
			Hostname []string `json:"hostname"`
			Op       []string `json:"op"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
		} `json:"user_end"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type UserLogin []struct {
	Data struct {
		UserLogin struct {
			Acct     []string `json:"acct"`
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Exe      []string `json:"exe"`
			Hostname []string `json:"hostname"`
			ID       []string `json:"id"`
			Op       []string `json:"op"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
		} `json:"user_login"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}

type UserStart []struct {
	Data struct {
		UserStart struct {
			Acct     []string `json:"acct"`
			Addr     []string `json:"addr"`
			Auid     []string `json:"auid"`
			Exe      []string `json:"exe"`
			Grantors []string `json:"grantors"`
			Hostname []string `json:"hostname"`
			Op       []string `json:"op"`
			Pid      []string `json:"pid"`
			Res      []string `json:"res"`
			Ses      []string `json:"ses"`
			Terminal []string `json:"terminal"`
			UID      []string `json:"uid"`
		} `json:"user_start"`
	} `json:"data"`
	Serial int64  `json:"serial"`
	Time   string `json:"time"`
}
