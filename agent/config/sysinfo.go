package config

import (
	"os"
	"io"
	"strings"
	"bufio"
)


func ReadFile2Map(name string)  (map[string] string, error){

	fi,err := os.Open(name)  
    if err != nil{  
        return nil, err  
    }  
    defer fi.Close()  
	result := make(map[string] string, 10)

    buf := bufio.NewReader(fi)
    for {
		line, err := buf.ReadString('\n')
		if err != nil{  
			if err == io.EOF {
                
				break
			} else {
				return nil, err  
			}
		}  
        line = strings.TrimSpace(line)
        if err != nil {
            if err == io.EOF {
                break
            } else {
                return nil, err  
            }
		}

		//too short
		if len(line) < 2 {
			continue
		}
		//comment line
		if strings.Index(line, "#") >= 0 {
			continue
		}
		//no key
		if strings.Index(line, "=") < 1 {
			continue
		}

		data := strings.Split(line, "=")
		//no value
		if len(data) <2 || len(strings.TrimSpace(data[0])) <1 ||  len(strings.TrimSpace(data[1])) <1 {
			continue
		}
		result[strings.TrimSpace(data[0])] = strings.TrimSpace(data[1])

    }

    return result, nil

}
