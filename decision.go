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

type Attack struct {
	description string
	classification string
	src string
	dst string
}

func snortParseAlerts(out string)map[string][]Attack{
	scores := make(map[string][]Attack)
	lines := strings.Split(out, "\n")
	for i:=0; i<len(lines)-1; i++{
		pat := regexp.MustCompile(`\[Class.*?\]`)
		class := pat.FindString(lines[i])[17:]
		class = class[:len(class)-1]
		srcpat := regexp.MustCompile(`\}.*?\->`)
		src := srcpat.FindString(lines[i])[2:]
		src = src[:len(src)-3]
		dstpat := regexp.MustCompile(`\>.*`)
		dst := dstpat.FindString(lines[i])[2:]
		scores[class] = append(scores[class], Attack{lines[i], class, src, dst})
	}
	return scores
}

func snortDetectorRoutine(c chan map[string][]Attack, pcapPath string, confPath string)map[string][]Attack{
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
		fmt.Printf("\t%s - score: %d\n", key, len(val))
	}

	c <- scores
	return scores
}

func attackDetector()map[string][]Attack{
	c := make(chan map[string][]Attack)
	go snortDetectorRoutine(c, os.Args[1], "/etc/snort/snort.conf")
	//go snortDetectorRoutine(c, os.Args[1], "/etc/snort/snortDoS.conf")
	//go snortDetectorRoutine(c, os.Args[1], "/etc/snort/snortCommunity.conf")
	//go snortDetectorRoutine(c, os.Args[1], "/etc/snort/snortWeb.conf")

	numRoutines := 1
	routineMaps := make([]map[string][]Attack, numRoutines)
	aggregated := make(map[string][]Attack)
	for i := 0; i < numRoutines; i++ {
		routineMaps[i] = <-c
		for key, val := range routineMaps[i]{
			for _, val2 := range val{
				aggregated[key] = append(aggregated[key], val2)
			}
		}
	}
	close(c)
	fmt.Printf("Aggregated Results:\n")
	for key, val := range aggregated{
		fmt.Printf("\t%s - score: %d\n", key, len(val))
	}
	return aggregated
}

func querySecurityFunctionDatabase(attacks []Attack)int{
	numAttacks := 0
	for _, val := range attacks{
		if val.classification == "Attempted Denial of Service"{
			fmt.Printf("\tDDoS detected - initializing RPL black hole mitigation\n")
			fmt.Printf("\t\t%s -> %s\n", val.src, val.dst)
			numAttacks++
		}
	}
	return numAttacks
}

func securityFunctionSelection(wg *sync.WaitGroup){
	defer wg.Done()
	aggregated := attackDetector()
	fmt.Printf("\nSecurity Function Selection\n")
	numAttacks := 0
	for _, val := range aggregated{
		numAttacks += querySecurityFunctionDatabase(val)
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
