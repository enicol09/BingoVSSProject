package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

var addr = flag.String("addr", "localhost:8080", "http service address")
var clientID = flag.String("id", "0", "client ID")

func main() {
	flag.Parse()
	log.SetFlags(0)

	conn, _, err := websocket.DefaultDialer.Dial("ws://"+*addr, nil)
	if err != nil {
		log.Fatal("Dial:", err)
	}
	defer conn.Close()

	// Sending the initial message (the client's ID)
	err = conn.WriteMessage(websocket.TextMessage, []byte(*clientID))
	if err != nil {
		log.Println("Write:", err)
		conn.Close()
		return
	}

	rowCount := 0 // Counter for "row"
	colCount := 0 // Counter for "column"

	// Read messages from the server and print to stdout
	go func() {
		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				log.Println("Read:", err)
				conn.Close()
				return
			}

			if messageType == websocket.TextMessage {
				fmt.Printf("%s\n", message)

				// Count the occurrence of "row"
				rowCount += bytes.Count(message, []byte("row"))
				colCount += bytes.Count(message, []byte("column"))

				// Do something when "row" appears a certain number of times
				if rowCount >= 2 {
					fmt.Println("=============================================")
					fmt.Println("I have enough shares to reconstruct my column")
					fmt.Println("=============================================")

					// Perform some action here
					rowCount = 0 // Reset counter
				}
				if colCount >= 4+1 {
					fmt.Println("=============================================")
					fmt.Println("I have enough shares to reconstruct my column")
					fmt.Println("=============================================")

					// Perform some action here
					colCount = 0 // Reset counter
				}
			}
		}
	}()

	// Read from stdin and write to the server
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text := scanner.Text()
		text = strings.TrimSpace(text)
		if text == "quit" || text == "exit" {
			break
		}

		err = conn.WriteMessage(websocket.TextMessage, []byte(text))
		if err != nil {
			log.Println("Write:", err)
			conn.Close()
			return
		}
	}

	if scanner.Err() != nil {
		log.Println("Scanner error:", scanner.Err())
		conn.Close()
		return
	}
}
