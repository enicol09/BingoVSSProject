package main

import (
	vss "BingoVSS/Bingo"
	kzg "BingoVSS/Internal/Biv_KZG"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/drand/kyber"
	"github.com/gorilla/websocket"
)

var (
	clients  = make(map[*websocket.Conn]string) // client connection and client ID
	mu       sync.Mutex
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	clientCount      = 0
	maxClientCount   = 4 // Maximum number of clients
	reconstructCount = 0
	consistent       = 0
)

func main() {
	http.HandleFunc("/", handleConnection)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Println(err)
		return
	}
}

func broadcast(message string) {
	mu.Lock()
	defer mu.Unlock()
	for conn := range clients {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			log.Printf("Error broadcasting message to client: %v", err)
		}
	}
}

func closeAllClients() {
	mu.Lock()
	defer mu.Unlock()
	for conn := range clients {
		conn.Close()
	}
	clients = make(map[*websocket.Conn]string)
	clientCount = 0
}

func handleConnection(w http.ResponseWriter, r *http.Request) {

	reconstructionChannel := make(chan bool)

	mu.Lock()
	if clientCount >= maxClientCount {
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		_, err := w.Write([]byte("Maximum client limit reached"))
		if err != nil {
			log.Println(err)
			return
		}
		return
	}
	clientCount++
	mu.Unlock()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer closeAllClients()

	_, msg, err := conn.ReadMessage()
	if err != nil {
		log.Println(err)
		return
	}

	clientID := string(msg)
	mu.Lock()
	clients[conn] = clientID
	mu.Unlock()

	// Display all connected client IDs
	mu.Lock()
	fmt.Println("Pariticipants:")
	for _, id := range clients {
		fmt.Println("We have a new participant = ", id)
	}
	mu.Unlock()

	// If maxClientCount reached, broadcast the message
	if clientCount == maxClientCount {
		broadcast("Maximum client limit reached")
		broadcast("-----------------------------------------------------------")
		broadcast("We will now begin the Bingo secret sharing! Are you excited?")
		broadcast("-----------------------------------------------------------")
		g := vss.NewSuite()
		//Create a Random number of secrets m
		m := 9
		secrets := make([]vss.Secret, m)
		for i := 0; i < m; i++ {
			secrets[i] = *vss.NewSecret(i, *g)
		}
		broadcast("I have create some secrets, specifically 9 secrets.")

		d_1 := 4
		d_2 := 2
		n := maxClientCount

		vn := make([]kyber.Scalar, n+1)
		for i := 0; i < n+1; i++ {
			vn[i] = g.ReturnSuite().G1().Scalar().SetInt64(int64(i))
		}

		setup, _ := kzg.NewKzgSetup(d_1+1, g.ReturnSuite())
		sh_setup := kzg.NewShareSetup(setup.ReturnT_1(), setup.ReturnT_2(), setup.ReturnT_u(), g.ReturnSuite(), setup.ReturnG_u(), setup.ReturnG_1(), setup.ReturnVal())

		verifiers := make([]vss.Verifier, maxClientCount+1)

		cm := make([]kyber.Point, n)

		for i := 0; i <= maxClientCount+1; i++ {
			if i == 0 {
				CM, coem, ver := vss.BingoShareDealer(secrets, d_1, d_2, n, 0, *g, setup)
				verifiers = ver
				broadcast("The commitments are the following: ")
				BroadcastCommitments(CM)
				cm = kzg.PartialEval(setup, CM, coem, vn)
				broadcast("-----------------------------------------------------------")
				// Wait for 5 seconds
				time.Sleep(20 * time.Second)
				broadcast("=== Sending polynomials to each participant ====")
				time.Sleep(20 * time.Second)
				sendPolynomials(verifiers, maxClientCount)

			} else {
				vss.BingoShare(verifiers, d_1, d_2, n, i-1, cm, *g, sh_setup, setup)

				if verifiers[i-1].SendStatus() == ("correct polynomial") {

					if i-1 == n-1 {
						time.Sleep(20 * time.Second)
						str := strconv.Itoa(i - 1)
						sendToSpecificClient(str, "I am not consistent with the polynomials given")
						verifiers[i-1].UpdateStatus("has sent rows")

					} else {

						str := strconv.Itoa(i - 1)
						sendToSpecificClient(str, "I am consistent with the polynomials given by dealer")
						handleSending(verifiers, i-1, d_1, d_2, n, i-1)
						consistent++
						verifiers[i-1].UpdateStatus("has sent rows")

					}

				}
			}

		}

		for i := 0; i <= n-1; i++ {
			vss.BingoShare(verifiers, d_1, d_2, n, i, cm, *g, sh_setup, setup)
			handleSendingCol(verifiers, i, d_1, d_2, n, i-1)
			verifiers[i].UpdateStatus("Done")
		}

		verifiers[3].UpdateStatus("missing polynomial")

		for i := 0; i <= n-1; i++ {
			if verifiers[i].SendStatus() == "missing polynomial" {
				sender := strconv.Itoa(i)
				sendToSpecificClient(sender, "I am attempting to reconstruct my polynomial.\n"+"-----------------------------------------------------------\n")

				vss.BingoShare(verifiers, d_1, d_2, n, i, cm, *g, sh_setup, setup)

				verifiers[i].UpdateStatus("Done")
				consistent++
			}

		}

		if consistent == maxClientCount+1 {
			broadcast("All the shares are correct. Therefore, the secret sharing has been completed. You can reconstruct the secrets if you want now. Just sent -Reconstruct-")

		}
		// Use a goroutine to wait for the signal to execute reconstruction logic
		go func() {
			<-reconstructionChannel

			str := strconv.Itoa(0)
			x := vss.BingoReconstruct(verifiers, 0, sh_setup, 0, d_2, cm)

			xBytes, err := x.MarshalBinary()
			if err != nil {
				panic(err)
			}

			// Convert bytes to a hex string for easy storage/transmission.
			xHex := hex.EncodeToString(xBytes)

			broadcast("Secret at place " + str + " equals with " + xHex)

			xBytes, err = secrets[0].SendSecret().MarshalBinary()
			if err != nil {
				panic(err)
			}

			xHex = hex.EncodeToString(xBytes)

			broadcast("The secret that was supposed to be equals with " + xHex)

		}()

	}

	for {
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Removed client ID: %s and closing all connections\n", clientID)
			return
		}

		if messageType == websocket.TextMessage {
			log.Printf("Received message from client ID %s: %s\n", clientID, string(msg))
		}
		receivedMessage := string(msg)

		if receivedMessage == "Rec" {
			mu.Lock()
			reconstructCount++

			mu.Unlock()

			if reconstructCount > 2 {
				reconstructionChannel <- true
			}
		}
	}
}

func handleSendingCol(verifiers []vss.Verifier, x, d_1, d_2, n, i2 int) {

	for i := 0; i < len(verifiers)-1; i++ {
		if verifiers[i].SendProofsCol()[x].ReturnY_1() != nil {
			a_x := verifiers[i].SendProofsCol()[x].ReturnY_1()
			a_xi := verifiers[i].SendProofsCol()[x].ReturnY_2()
			p := verifiers[i].SendProofsCol()[x].ReturnP()

			sender := strconv.Itoa(x)
			receiver := strconv.Itoa(i)

			pointBytes, _ := a_x.MarshalBinary()
			a_x_s := hex.EncodeToString(pointBytes)

			pointBytes, _ = a_xi.MarshalBinary()
			a_x_si := hex.EncodeToString(pointBytes)

			pointBytes, _ = p.MarshalBinary()
			p_i := hex.EncodeToString(pointBytes)

			str := "a_" + sender + " = " + a_x_s + "\n a'_" + sender + " = " + a_x_si + "\n p_" + sender + " = " + p_i

			sendToSpecificClient(sender, "sending <<column>> to "+receiver+"\n"+"-----------------------------------------------------------\n")

			sendToSpecificClient(receiver, "<<column>> from "+sender+"\n"+str+"-----------------------------------------------------------\n")

		}
	}
}

func arrayToString(scalars []kyber.Scalar) string {
	var elements []string
	for _, scalar := range scalars {
		scalarBytes, err := scalar.MarshalBinary()
		if err != nil {
			panic(err)
		}

		// Convert the individual scalar's bytes to hex string
		scalarHex := hex.EncodeToString(scalarBytes)

		// Append this hex string to the list of elements
		elements = append(elements, scalarHex)
	}

	// Combine all the hex strings separated by a space
	combinedString := strings.Join(elements, " ")

	return combinedString
}

func sendPolynomials(verifiers []vss.Verifier, maxClientCount int) {
	for i := 0; i < maxClientCount; i++ {
		str := strconv.Itoa(i)
		a_x := arrayToString(verifiers[i].SendPolynomials().Coefficients())
		a_xj := arrayToString(verifiers[i].SendPolynomials().Coefficients_2())

		str_all := " rows \n" + "a(x)= " + a_x + " \n" + "a'(x)= " + a_xj
		sendToSpecificClient(str, "-----------------------------------------------------------")
		sendToSpecificClient(str, str_all)
		sendToSpecificClient(str, "-----------------------------------------------------------")
	}
}

func BroadcastCommitments(CM []kyber.Point) {

	for i := 0; i < len(CM); i++ {
		pointBytes, err := CM[i].MarshalBinary()
		if err != nil {
			panic(err)
		}

		// Convert the byte slice to a hex string
		pointHex := hex.EncodeToString(pointBytes)
		str := strconv.Itoa(i)

		broadcast("<commits> " + str + " =" + pointHex)
		broadcast("-----------------------------------------------------------")

	}
}

func handleSending(verifiers []vss.Verifier, x, d_1, d_2, n, i2 int) {

	for i := 0; i < len(verifiers)-1; i++ {
		if verifiers[i].SendProofsRow()[x].ReturnY_1() != nil {
			a_x := verifiers[i].SendProofsRow()[x].ReturnY_1()
			a_xi := verifiers[i].SendProofsRow()[x].ReturnY_2()
			p := verifiers[i].SendProofsRow()[x].ReturnP()

			sender := strconv.Itoa(x)
			receiver := strconv.Itoa(i)

			pointBytes, _ := a_x.MarshalBinary()
			a_x_s := hex.EncodeToString(pointBytes)

			pointBytes, _ = a_xi.MarshalBinary()
			a_x_si := hex.EncodeToString(pointBytes)

			pointBytes, _ = p.MarshalBinary()
			p_i := hex.EncodeToString(pointBytes)

			str := "a_" + sender + " = " + a_x_s + "\n a'_" + sender + " = " + a_x_si + "\n p_" + sender + " = " + p_i

			sendToSpecificClient(sender, "sending <<row>> to "+receiver+"\n"+"-----------------------------------------------------------\n")

			sendToSpecificClient(receiver, "<<row>> from "+sender+" \n"+str+"\n"+"-----------------------------------------------------------\n")
		}
	}
}

func sendToSpecificClient(clientID string, message string) {
	mu.Lock()
	defer mu.Unlock()

	for conn, id := range clients {
		if id == clientID {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
				log.Printf("Error sending message to client %s: %v", clientID, err)
			}
			break
		}
	}
}
