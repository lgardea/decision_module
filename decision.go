package main

import ("fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
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

func snortDetectorRoutine(c chan map[string]int, pcapPath string, confPath string)map[string]int{
	now := time.Now()
	defer func() {
		fmt.Print("\tRuntime = ")
		fmt.Println(time.Now().Sub(now))
	}()

	argstr := []string{"-c", "sudo snort -r " + pcapPath + " -c " + confPath + " -A console -q"}
	out, err := exec.Command("/bin/sh", argstr...).Output()
	if err != nil{
		log.Fatalf("%v: exec: snort", err)
	}
	scores := snortParseAlerts(string(out))

	fmt.Printf("Snort Attack Detector {%s} Results:\n", confPath)
	for key, val := range scores{
		fmt.Printf("\t%s - score: %d\n", key, val)
	}

	c <- scores
	return scores
}

func attackDetector()map[string]int{
	c := make(chan map[string]int)
	go snortDetectorRoutine(c, os.Args[1], "/etc/snort/snort.conf")
	go snortDetectorRoutine(c, os.Args[1], "/etc/snort/snortDoS.conf")
	go snortDetectorRoutine(c, os.Args[1], "/etc/snort/snortCommunity.conf")
	go snortDetectorRoutine(c, os.Args[1], "/etc/snort/snortWeb.conf")
	numRoutines := 4
	
	routineMaps := make([]map[string]int, numRoutines)
	aggregated := make(map[string]int)
	for i := 0; i < numRoutines; i++ {
		routineMaps[i] = <-c
		for key, val := range routineMaps[i]{
			aggregated[key] = aggregated[key] + val
		}
	}
	close(c)
	fmt.Printf("Aggregated Results:\n")
	for key, val := range aggregated{
		fmt.Printf("\t%s - score: %d\n", key, val)
	}
	return aggregated
}

func querySecurityFunctionDatabase(attack string)int{
	numAttacks := 0
	if attack == "Attempted Denial of Service"{
		fmt.Printf("\tDDoS detected - initializing RPL black hole mitigation\n")
		numAttacks++
	}
	return numAttacks
}

func securityFunctionSelection(wg *sync.WaitGroup){
	defer wg.Done()
	aggregated := attackDetector()
	fmt.Printf("\nSecurity Function Selection\n")
	numAttacks := 0
	for key, _ := range aggregated{
		numAttacks += querySecurityFunctionDatabase(key)
	}
	if numAttacks == 0{
		fmt.Printf("\tNo mitigations initialized\n")
	}
}

func main(){
	now := time.Now()
	defer func() {
		fmt.Print("\tTotal Runtime = ")
		fmt.Println(time.Now().Sub(now))
	}()

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

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go securityFunctionSelection(wg)
	wg.Wait()
}
