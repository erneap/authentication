package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func Config(key string) string {
	err := godotenv.Load(".env")
	if err != nil {
		log.Print("Error loading .env file")
		log.Println(err.Error())
	}

	return os.Getenv(key)
}
