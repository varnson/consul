package config

import (
	"fmt"
	"os"
	"bufio"
)

type SysInfoError struct {
	file string
	msg string
	Error() string
}
func (*SysInfoError) Error() string{
	return msg
}

func ReadFile2Map(name string)  (map[string] string, error){
	if nil == name || len(name) < 5{
		return nil, SysInfoError(name, "file name error")
	}

	fi,err := os.Open(path)  
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
		if len(data) <2 || len(strings.Trim(data[0])) <1 ||  len(strings.Trim(data[1])) <1 {
			continue
		}
		result[strings.Trim(data[0])] = strings.Trim(data[1])

    }

    return result   

}
