package main

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gocarina/gocsv"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// db is our global database variable
var db *sql.DB

// calcHash calculates the hash of the data
func calcHash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	hash := fmt.Sprintf("%x", h.Sum(nil))
	return hash
}

// initDB initializes the database connection
func initDB(databaseFile string) {
	var err error
	db, err = sql.Open("sqlite3", databaseFile)
	if err != nil {
		panic(err)
	}
	fmt.Println("Initalized connection with " + databaseFile + "!")
}

// createTable creates the netflow table if it doesn't already exist
func createTable() {
	statement1 := "create table IF NOT EXISTS Router_Logs (log_id text primary key not null unique, source_address text not null, destination_address text not null, source_port integer not null, destination_port integer not null, protocol integer not null, packets interger not null, bytes interger not null, flags text not null, start_time text not null, duration real not null, end_time text not null, sensor text not null, hash text not null unique);"
	_, err := db.Exec(statement1)
	if err != nil {
		panic(err)
	}
	statement2 := "create table IF NOT EXISTS Linux_Logs (log_id text primary key not null unique, log_type text not null, date_time text not null, data text not null, hash text not null unique);"
	_, err = db.Exec(statement2)
	if err != nil {
		panic(err)
	}
	statement3 := "create table IF NOT EXISTS Windows_Logs (log_id text primary key not null unique, keywords text not null, date_time text not null, source text not null, event_id integer not null, task_category text not null, task_description text not null, hash text not null unique);"
	_, err = db.Exec(statement3)
	if err != nil {
		panic(err)
	}
	statement4 := "create table IF NOT EXISTS Log_Records (log_record_id integer primary key autoincrement, log_type text not null, windows_log_id text null, linux_log_id text null, router_log_id text null, foreign key(windows_log_id) references Windows_Logs(log_id), foreign key(linux_log_id) references Linux_Logs(log_id), foreign key(router_log_id) references Router_Logs(log_id));"
	_, err = db.Exec(statement4)
	if err != nil {
		panic(err)
	}
}

// parseRwcutOutput parses the table like format output from rwcut and puts each row into a list to be imported.
func parseRwcutOutput(file string) []rwcut {
	data := []rwcut{}
	in, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	defer in.Close()
	scanner := bufio.NewScanner(in)
	skipFirst := true
	for scanner.Scan() {
		if skipFirst {
			skipFirst = false
			continue
		}
		record := strings.Split(scanner.Text(), "|")
		id, err := uuid.NewUUID()
		if err != nil {
			panic(err)
		}
		tmpRwcut := rwcut{
			ID:            id.String(),
			SourceIP:      strings.TrimSpace(record[0]),
			DestinationIP: strings.TrimSpace(record[1]),
			Flags:         strings.TrimSpace(record[7]),
			StartTime:     strings.TrimSpace(record[8]),
			EndTime:       strings.TrimSpace(record[10]),
			Sensor:        strings.TrimSpace(record[11]),
		}

		sport, err := strconv.Atoi(strings.TrimSpace(record[2]))
		if err != nil {
			panic(err)
		}
		tmpRwcut.SourcePort = sport
		dport, err := strconv.Atoi(strings.TrimSpace(record[3]))
		if err != nil {
			panic(err)
		}
		tmpRwcut.DestinationPort = dport
		proto, err := strconv.Atoi(strings.TrimSpace(record[4]))
		if err != nil {
			panic(err)
		}
		tmpRwcut.Protocol = proto
		packets, err := strconv.Atoi(strings.TrimSpace(record[5]))
		if err != nil {
			panic(err)
		}
		tmpRwcut.Packets = packets
		bytes, err := strconv.Atoi(strings.TrimSpace(record[6]))
		if err != nil {
			panic(err)
		}
		tmpRwcut.Bytes = bytes
		duration, err := strconv.ParseFloat(strings.TrimSpace(record[9]), 32)
		if err != nil {
			panic(err)
		}
		tmpRwcut.Duration = duration
		tmpRwcut.Hash = calcHash(fmt.Sprintf("%s-%s-%d-%d-%d-%d-%d-%s-%s-%f-%s-%s", tmpRwcut.SourceIP, tmpRwcut.DestinationIP, tmpRwcut.SourcePort, tmpRwcut.DestinationPort, tmpRwcut.Protocol, tmpRwcut.Packets, tmpRwcut.Bytes, tmpRwcut.Flags, tmpRwcut.StartTime, tmpRwcut.Duration, tmpRwcut.EndTime, tmpRwcut.Sensor))
		data = append(data, tmpRwcut)
	}
	return data
}

// insertRouterData inserts the rwcut data into the database
func insertRouterData(data []rwcut) {
	transaction, err := db.Begin()
	if err != nil {
		panic(err)
	}
	statement, err := transaction.Prepare("insert into Router_Logs (log_id, source_address, destination_address, source_port, destination_port, protocol, packets, bytes, flags, start_time, duration, end_time, sensor, hash) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		panic(err)
	}
	defer statement.Close()
	for _, record := range data {
		_, err := statement.Exec(record.ID, record.SourceIP, record.DestinationIP, record.SourcePort, record.DestinationPort, record.Protocol, record.Packets, record.Bytes, record.Flags, record.StartTime, record.Duration, record.EndTime, record.Sensor, record.Hash)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				continue
			} else {
				panic(err)
			}
		}
		createLogRecord("router", record.ID, transaction)
	}
	transaction.Commit()

	fmt.Println("Router Data has been inserted!")
}

func insertWindowsData(data []windowsLog) {
	transaction, err := db.Begin()
	if err != nil {
		panic(err)
	}
	statement, err := transaction.Prepare("insert into Windows_Logs (log_id, keywords, date_time, source, event_id, task_category, task_description, hash) values(?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		panic(err)
	}
	defer statement.Close()
	for _, record := range data {
		_, err := statement.Exec(record.ID, record.Keywords, record.DateTime, record.Source, record.EventID, record.TaskCategory, record.TaskDescription, record.Hash)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				continue
			} else {
				panic(err)
			}
		}

		createLogRecord("windows", record.ID, transaction)
	}
	transaction.Commit()

	fmt.Println("Windows Data has been inserted!")
}

func parseLinuxLogs(jsonLogDirectory string) []linuxLog {
	logs := []linuxLog{}
	err := filepath.Walk(jsonLogDirectory, func(path string, info os.FileInfo, err error) error {
		if info.Name() == "json" {
			return nil
		}
		name := strings.Split(info.Name(), ".")[0]
		j, err := os.Open(jsonLogDirectory + name + ".json")
		if err != nil {
			return err
		}
		data, err := ioutil.ReadAll(j)
		if err != nil {
			return err
		}

		switch name {
		case "AVC":
			tmp := Avc{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "BPRM_FCAPS":
			tmp := BprmFcaps{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "CONFIG_CHANGE":
			tmp := ConfigChange{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "CRED_ACQ":
			tmp := CredAcq{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "CRED_DISP":
			tmp := CredDisp{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "CRED_REFR":
			tmp := CredRefr{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "DAEMON_START":
			tmp := DaemonStart{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "EXECVE":
			tmp := Execve{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "LOGIN":
			tmp := Login{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "PATH":
			tmp := Path{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "PROCTITLE":
			tmp := Proctitle{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "SERVICE_START":
			tmp := ServiceStart{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "SERVICE_STOP":
			tmp := ServiceStop{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "SYSCALL":
			tmp := Syscall{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "SYSTEM_BOOT":
			tmp := SystemBoot{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "SYSTEM_RUNLEVEL":
			tmp := SystemRunlevel{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "USER_ACCT":
			tmp := UserAcct{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "USER_AUTH":
			tmp := UserAuth{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "USER_CMD":
			tmp := UserCmd{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "USER_END":
			tmp := UserEnd{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "USER_LOGIN":
			tmp := UserLogin{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		case "USER_START":
			tmp := UserStart{}
			err = json.Unmarshal(data, &tmp)
			if err != nil {
				return err
			}
			for _, t := range tmp {
				id, err := uuid.NewUUID()
				if err != nil {
					return err
				}
				tmpS, err := json.Marshal(t)
				if err != nil {
					return err
				}
				logs = append(logs, linuxLog{
					ID:       id.String(),
					Type:     name,
					DateTime: t.Time,
					Data:     string(tmpS),
					Hash:     calcHash(fmt.Sprintf("%s-%s-%s", name, t.Time, string(tmpS))),
				})
			}
			break
		}

		return nil
	})
	if err != nil {
		panic(err)
	}
	return logs
}

func insertLinuxLogs(data []linuxLog) {
	transaction, err := db.Begin()
	if err != nil {
		panic(err)
	}
	statement, err := transaction.Prepare("insert into Linux_Logs (log_id, log_type, date_time, data, hash) values(?, ?, ?, ?, ?)")
	if err != nil {
		panic(err)
	}
	defer statement.Close()
	for _, record := range data {
		_, err := statement.Exec(record.ID, record.Type, record.DateTime, record.Data, record.Hash)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				continue
			} else {
				panic(err)
			}
		}
		createLogRecord("linux", record.ID, transaction)
	}
	transaction.Commit()

	fmt.Println("Data has been inserted!")
}

// createLogRecord creates the log record entry in the database table after a new log is inserted
func createLogRecord(logType, logID string, transaction *sql.Tx) {
	var err error
	var statement = &sql.Stmt{}
	switch logType {
	case "router":
		statement, err = transaction.Prepare("insert into Log_Records (log_type, router_log_id) values(?, ?)")
		if err != nil {
			panic(err)
		}
		break
	case "linux":
		statement, err = transaction.Prepare("insert into Log_Records (log_type, linux_log_id) values(?, ?)")
		if err != nil {
			panic(err)
		}
		break
	case "windows":
		statement, err = transaction.Prepare("insert into Log_Records (log_type, windows_log_id) values(?, ?)")
		if err != nil {
			panic(err)
		}
		break
	}
	defer statement.Close()
	_, err = statement.Exec(logType, logID)
	if err != nil {
		panic(err)
	}
}

func parseWindowsLogs(auditLogCSV string) []windowsLog {
	logs, err := os.Open(auditLogCSV)
	if err != nil {
		panic(err)
	}
	defer logs.Close()
	wLogs := []windowsLog{}
	err = gocsv.UnmarshalFile(logs, &wLogs)
	if err != nil {
		panic(err)
	}

	// we need to loop through and assign UUIDs now
	for i, l := range wLogs {
		id, err := uuid.NewUUID()
		if err != nil {
			panic(err)
		}
		l.ID = id.String()
		l.Hash = calcHash(fmt.Sprintf("%s-%s-%s-%d-%s-%s", l.Keywords, l.DateTime, l.Source, l.EventID, l.TaskCategory, l.TaskDescription))
		wLogs[i] = l
	}
	return wLogs
}

func main() {
	launchArgs := os.Args
	if len(launchArgs) != 5 {
		fmt.Println("You're missing some launch arugments!")
		fmt.Println("Example usage: ./audit-logs-importer logs.db flow_from_rwcut.txt linux/auditd/logs/json/output/folder/ windows_audit_log.csv")
		os.Exit(1)
	}
	initDB(launchArgs[1])
	createTable()
	data := parseRwcutOutput(launchArgs[2])
	fmt.Println("Inserting flow records from " + launchArgs[2] + " into database now!")
	insertRouterData(data)
	fmt.Println("Importing of silk rwcut netflow data into database has finished!")
	fmt.Println("Parsing linux logs now!")
	lLogs := parseLinuxLogs(launchArgs[3])
	fmt.Println("Parsing complete!")
	fmt.Println("Importing linux logs now!")
	insertLinuxLogs(lLogs)
	fmt.Println("Linux log importing completed!")
	fmt.Println("Parsing Windows Logs now!")
	wLogs := parseWindowsLogs(launchArgs[4])
	fmt.Println("Parsing complete!")
	fmt.Println("Importing Windows Logs now!")
	insertWindowsData(wLogs)
	fmt.Println("All logs have now been imported! Goodbye!")
	db.Close()

}
