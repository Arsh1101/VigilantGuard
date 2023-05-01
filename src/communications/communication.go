package comunication

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	pb "gobpf-test/src/filetransfer"
)

const (
	address = "localhost:50051"
	thePath = "/var/log/vigilant-guard/"
)

func fileStreaming(filePath string, filename string) bool {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	// Check if server is running
	c := pb.NewFileTransferClient(conn)
	// Open the file to send.
	file, err := os.Open(filePath + filename)
	if err != nil {
		log.Fatalf("could not open file: %v", err)
	}
	defer file.Close()
	// Create a stream to send the file chunks.
	stream, err := c.SendFile(context.Background())
	if conn.GetState() == connectivity.Ready {
		if err != nil {
			log.Fatalf("could not send file: %v", err)
		}

		// Send the filename and file data to the server.
		chunkSize := 1024 // 1KB
		buf := make([]byte, chunkSize)
		for {
			n, err := file.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatalf("could not read file: %v", err)
			}
			if err := stream.Send(&pb.SendFileRequest{Filename: filename, Data: buf[:n]}); err != nil {
				log.Fatalf("could not send chunk: %v", err)
			}
		}

		// Close the stream and wait for the response from the server.
		resp, err := stream.CloseAndRecv()
		if err != nil {
			log.Fatalf("could not receive response: %v", err)
		}
		log.Printf("Response: %v", resp)
		return true
	}
	return false
}

func findFilesByDateRange(dir string, start time.Time, end time.Time) []fs.FileInfo {
	fileSystem := os.DirFS(dir)
	var files []fs.FileInfo
	if err := fs.WalkDir(fileSystem, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Fatal(err)
		}
		fileInfo, err := d.Info()
		if err != nil {
			return err
		}
		stat := fileInfo.Sys().(*syscall.Stat_t)
		cDate := time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec).UTC()
		if !d.IsDir() && (cDate.After(start) && cDate.Before(end)) {
			files = append(files, fileInfo)
		}
		return nil
	}); err != nil {
		return nil
	}
	return files
}

func serverConnectionCheck() bool {
	result := true
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("did not connect: %v\n", err)
		result = false
	} else {
		log.Printf("did connect: %v\n", err)
	}
	defer conn.Close()
	return result
}

func TransferLogs(start time.Time) time.Time {
	//Get Lo
	end := time.Now()
	files := findFilesByDateRange(thePath, start, end)
	for i, file := range files {
		fmt.Println(i)
		if !fileStreaming(thePath, file.Name()) {
			time.Sleep(1 * time.Second)
			log.Println("Could not send log.")
		}
	}
	if len(files) > 0 {
		return end
	}
	return start
}
