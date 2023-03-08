package main

import ("fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"encoding/csv"
	"io"
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

func fastnetmonParseAlerts(alertPath string)map[string][]Attack{
	scores := make(map[string][]Attack)
	f, err := os.Open(alertPath)
	if err != nil{
		log.Fatal(err)
	}
	defer f.Close()
	csvReader := csv.NewReader(f)
	for {
		rec, err := csvReader.Read()
		if err == io.EOF{
			break
		}
		if err != nil{
			log.Fatal(err)
		}
		desc := "FastNetMon Guard: IP " + rec[0] + " blocked because " + rec[1] + " attack with power " + rec[2] + " pps"
		class := "Attempted Denial of Service"
		src := rec[0]
		dst := "Unknown"
		scores[class] = append(scores[class], Attack{desc, class, src, dst})
	}
	return scores
}

func fastnetmonDetectorRoutine(c chan map[string][]Attack, alertPath string)map[string][]Attack{
	now := time.Now()
	defer func() {
		fmt.Print("\tRuntime = ")
		fmt.Println(time.Now().Sub(now))
	}()

	scores := fastnetmonParseAlerts(alertPath)

	fmt.Printf("fastnetmon Attack Detector Results:\n")
	for key, val := range scores{
		fmt.Printf("\t%s - score: %d\n", key, len(val))
	}

	c <- scores
	return scores
}

func launchAttackDetectors(c chan map[string][]Attack)int{
	numRoutines := 0
	f, err := os.Open("controller.conf")
	if err != nil{
		log.Fatal(err)
	}
	defer f.Close()
	csvReader := csv.NewReader(f)
	csvReader.FieldsPerRecord = -1
	for {
		rec, err := csvReader.Read()
		if err == io.EOF{
			break
		}
		if err != nil{
			log.Fatal(err)
		}
		if rec[0] == "snort"{
			if _, err := os.Stat(rec[1]); err != nil{
				log.Fatal("Error: pcap does not exist or bad permission")
			}
			if _, err := os.Stat(rec[2]); err != nil{
				log.Fatal("Error: snort conf does not exist or bad permission")
			}
			go snortDetectorRoutine(c, rec[1], rec[2])
			numRoutines++
		} else if rec[0] == "fastnetmon"{
			if _, err := os.Stat(rec[1]); err != nil{
				log.Fatal("Error: fastnetmon note does not exist or bad permission")
			}
			go fastnetmonDetectorRoutine(c, rec[1])
			numRoutines++
		} else {
			log.Fatal("Error: unrecognized detector")
		}
	}

	return numRoutines
}

func attackDetector()map[string][]Attack{
	c := make(chan map[string][]Attack)
	numRoutines := launchAttackDetectors(c)
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

func securityFunctionSelection(){
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
	securityFunctionSelection()
}
