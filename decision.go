package main

import ("fmt"
	"os"
	"os/exec"
	"log"
	"sync"
	"strings"
	"regexp"
)

func snortParseAlerts(out string)map[string]int{
	scores := make(map[string]int)
	lines := strings.Split(out, "\n")
	for i:=0; i<len(lines)-1; i++{
		pat := regexp.MustCompile(`\[Class.*?\]`)
		class := pat.FindString(lines[i])[17:]
		class = class[:len(class)-1]
		scores[class] = scores[class] + 1
	}
	return scores
}

func snortDetectorRoutine(wg *sync.WaitGroup, pcapPath string)map[string]int{
	defer wg.Done()
	fmt.Println("path: " + pcapPath)
	argstr := []string{"-c", "sudo snort -r /home/lorenzo/Documents/firewall/2021-12-11-thru-13-server-activity-with-log4j-attempts.pcap -c /etc/snort/snort.conf -A console -q"}
	out, err := exec.Command("/bin/sh", argstr...).Output()
	if err != nil{
		log.Fatalf("%v: exec: snort", err)
	}
	scores := snortParseAlerts(string(out))

	for key, val := range scores{
		fmt.Printf("%s - score: %d\n", key, val)
	}

	return scores
}

func main(){
	f, err := os.OpenFile("controller.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil{
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	if len(os.Args) != 2{
		log.Fatal("Error: specify pcap path")
	}
	if _, err := os.Stat(os.Args[1]); err == nil{
		fmt.Println(os.Args[1] + " exists")
	} else{
		log.Fatal("Error: pcap does not exist or bad permission")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go snortDetectorRoutine(&wg, os.Args[1])
	wg.Wait()
}
