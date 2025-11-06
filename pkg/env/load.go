package env

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func Load(rootPath string) error {
	err := checkDotEnv(rootPath)
	if err != nil {
		return err
	}
	// read .env
	err = godotenv.Load(rootPath + "/.env")
	if err != nil {
		return err
	}

	return nil
}

func checkDotEnv(path string) error {
	err := createFileIfNotExists(fmt.Sprintf("%s/.env", path))
	if err != nil {
		return err
	}
	return nil
}

func createFileIfNotExists(path string) error {
	var _, err = os.Stat(path)
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			return err
		}

		defer func(file *os.File) {
			_ = file.Close()
		}(file)
	}
	return nil
}
