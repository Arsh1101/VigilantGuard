package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang gen_execve ./bpf/execve.bpf.c -- -I/usr/include/bpf -I.

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/unix"
)

type exec_data_t struct {
	Pid uint32
	//Arsh: get uid
	Uid    uint32
	F_name [32]byte
	Comm   [32]byte
}

// Arsh: Memory works.
// It should be other package in future.
const dbDriver = "sqlite3"

type Name struct {
	ID   int `db:"id"`
	Name string
}

var initOnce sync.Once
var db *sql.DB
var stmt *sql.Stmt

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
	var wg sync.WaitGroup
	id := make(chan int64)
	initOnce.Do(func() {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
		prepareInMemoryDbWorks()
		setlimit()
	})
	defer db.Close()
	defer stmt.Close()

	wg.Add(1)
	go transferFromDb(&wg, id)
	wg.Add(1)
	go exitSignal(&wg)
	defer wg.Wait()
	//
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
			temp := fmt.Sprintf("On cpu %02d %s ran : %d %s -> user : %d", ev.CPU, string(bytes.Trim(data.Comm[:], "\x00")), data.Pid, string(bytes.Trim(data.F_name[:], "\x00")), data.Uid)
			fmt.Println(temp)
			addedID := addNewRow(temp)
			if addedID > 0 {
				fmt.Printf("Inserted name with ID %d\n", addedID)
				id <- addedID
			} else {
				fmt.Println("Something was wrong in memory.")
			}
		}
	}
}

// Arsh: Memory works.
// It should be other package in future.
func prepareInMemoryDbWorks() {
	// create an in-memory sqlite database
	var err error
	db, err = sql.Open(dbDriver, ":memory:")
	if err != nil {
		log.Panic(err)

	}
	// create the names table
	_, err = db.Exec("CREATE TABLE names (id INTEGER PRIMARY KEY, name TEXT)")
	if err != nil {
		log.Panic(err)
	}
	// prepare the insert statement
	stmt, err = db.Prepare("INSERT INTO names (name) VALUES (?)")
	if err != nil {
		log.Panic(err)
	}
}

func addNewRow(name string) int64 {
	// insert the name into the database
	result, err := stmt.Exec(name)
	if err != nil {
		log.Println(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		log.Println(err)
	}
	return id
}

func transferFromDb(wg *sync.WaitGroup, id chan int64) {
	defer wg.Done()
	for lastID := range id {
		// query for new rows
		rows, err := db.Query("SELECT id, name FROM names WHERE id = ?;", int(lastID))
		if err != nil {
			log.Println(err)
		}
		// iterate over the rows and append to the text file
		for rows.Next() {
			var name Name
			err := rows.Scan(&name.ID, &name.Name)
			if err != nil {
				log.Println(err)
			}
			appendToFile(fmt.Sprintf("%d: %s\n", name.ID, name.Name))
		}
		rows.Close()
		deleteFromDb(int(lastID))
	}
}

func appendToFile(line string) {
	file, err := os.OpenFile("output.yaml", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Println(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	_, err = writer.WriteString(line)
	if err != nil {
		log.Println(err)
	}
	writer.Flush()
}

func deleteFromDb(lastID int) {
	//Delete the row from the database
	// It is not good if DB grows in memory, thats why these errors log as panic.
	statement, err := db.Prepare("delete from names where id = ?")
	if err != nil {
		log.Panic(err)
	}
	_, err = statement.Exec(lastID)
	if err != nil {
		log.Panic(err)
	}
	defer statement.Close()
}

// func getInput(wg *sync.WaitGroup, id chan int64) {
// 	defer wg.Done()
// 	scanner := bufio.NewScanner(os.Stdin)
// 	for {
// 		fmt.Print("Enter a name: ")
// 		if scanner.Scan() {
// 			name := scanner.Text()
// 			addedID := addNewRow(name)
// 			if addedID > 0 {
// 				fmt.Printf("Inserted name with ID %d\n", addedID)
// 				id <- addedID
// 			} else {
// 				fmt.Println("Something was wrong in memory.")
// 			}
// 		}
// 	}
// }

func exitSignal(wg *sync.WaitGroup) {
	defer wg.Done()
	sigs := make(chan os.Signal, 1)
	// Wait for a signal to be received
	sig := <-sigs
	fmt.Printf("\nSignal received: %v (type %T)\n", sig, sig)
}
