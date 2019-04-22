package logger

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	now = time.Now
)

//LogFile is used to setup a file based logger that also performs log rotation
type LogFile struct {
	//Name of the log file
	fileName string

	//full Name of the log file
	fullName string

	//rotate Name of the log file
	rotateName string

	//Path to the log file
	logPath string

	//Duration between each file rotation operation
	duration time.Duration

	//LastCreated represents the creation time of the latest log
	LastCreated time.Time

	//FileInfo is the pointer to the current file being written to
	FileInfo *os.File

	//MaxBytes is the maximum number of desired bytes for a log file
	MaxBytes int

	//BytesWritten is the number of bytes written in the current log file
	BytesWritten int64

	//acquire is the mutex utilized to ensure we have no concurrency issues
	acquire sync.Mutex
}

func (l *LogFile) openNew() error {
	// Extract the file extension
	fileExt := filepath.Ext(l.fileName)
	// If we have no file extension we append .log
	if fileExt == "" {
		fileExt = ".log"
	}
	// Remove the file extension from the filename
	fileName := strings.TrimSuffix(l.fileName, fileExt)
	// New file name has the format : filename-timestamp.extension
	createTime := now()
	l.rotateName = fileName + "-" + time.Unix(createTime.Unix(), 0).Format("20110203030406") + fileExt
	newfileName := fileName + fileExt
	newfilePath := filepath.Join(l.logPath, newfileName)
	l.fullName = newfilePath
	l.rotateName = filepath.Join(l.logPath, l.rotateName)
	// Try creating a file. We truncate the file because we are the only authority to write the logs
	filePointer, err := os.OpenFile(newfilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	l.FileInfo = filePointer
	// New file, new bytes tracker, new creation time :)
	l.LastCreated = createTime
	l.BytesWritten = 0
	return nil
}

func (l *LogFile) rotate() error {
	// Get the time from the last point of contact
	timeElapsed := time.Since(l.LastCreated)
	// Rotate if we hit the byte file limit or the time limit
	if (l.BytesWritten >= int64(l.MaxBytes) && (l.MaxBytes > 0)) || timeElapsed >= l.duration {
		l.FileInfo.Close()
		os.Rename(l.fullName, l.rotate)
		return l.openNew()
	}
	return nil
}

func (l *LogFile) Write(b []byte) (n int, err error) {
	l.acquire.Lock()
	defer l.acquire.Unlock()
	//Create a new file if we have no file to write to
	if l.FileInfo == nil {
		if err := l.openNew(); err != nil {
			return 0, err
		}
	}
	idx := strings.Index(string(b), "[DEBUG]")
	if idx > 15 && idx < 25 {
		return 0, nil
	}
	// Check for the last contact and rotate if necessary
	if err := l.rotate(); err != nil {
		return 0, err
	}
	l.BytesWritten += int64(len(b))
	return l.FileInfo.Write(b)
}
