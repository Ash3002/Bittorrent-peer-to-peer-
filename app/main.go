package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"unicode"
	"crypto/sha1"
	"sort"
	"net/http"
	"net/url"
	"io/ioutil"
	"crypto/rand"
	"net"
	"encoding/binary"
	"io"
	// bencode "github.com/jackpal/bencode-go" // Available if you need it!
)

// Ensures gofmt doesn't remove the "os" encoding/json import (feel free to remove this!)
var _ = json.Marshal

// Example:
// - 5:hello -> hello
// - 10:hello12345 -> hello12345
func decodeBencode(bencodedString string) (interface{}, error) {
	if len(bencodedString) == 0 {
		return nil, fmt.Errorf("Empty input")
	}
	if unicode.IsDigit(rune(bencodedString[0])) {
		var firstColonIndex int
		for i := 0; i < len(bencodedString); i++ {
			if bencodedString[i] == ':' {
				firstColonIndex = i
				break
			}
		}
		lengthStr := bencodedString[:firstColonIndex]
		length, err := strconv.Atoi(lengthStr)
		if err != nil {
			return "", err
		}
		return bencodedString[firstColonIndex+1 : firstColonIndex+1+length], nil
	} else if bencodedString[0] == 'i' {
		if len(bencodedString) < 3 || bencodedString[len(bencodedString)-1] != 'e' {
			return nil, fmt.Errorf("Malformed integer bencode")
		}
		val, err := strconv.Atoi(bencodedString[1 : len(bencodedString)-1])
		if err != nil {
			return nil, err
		}
		return val, nil
	} else if bencodedString[0] == 'l' {
		var result []interface{}
		idx := 1
		for idx < len(bencodedString) && bencodedString[idx] != 'e' {
			elem, n, err := decodeBencodeWithConsumed(bencodedString[idx:])
			if err != nil {
				return nil, err
			}
			result = append(result, elem)
			idx += n
		}
		if idx >= len(bencodedString) || bencodedString[idx] != 'e' {
			return nil, fmt.Errorf("List not terminated properly")
		}
		return result, nil
	} else if bencodedString[0] == 'd' {
		result := make(map[string]interface{})
		idx := 1
		for idx < len(bencodedString) && bencodedString[idx] != 'e' {
			keyVal, n, err := decodeBencodeWithConsumed(bencodedString[idx:])
			if err != nil {
				return nil, err
			}
			keyStr, ok := keyVal.(string)
			if !ok {
				return nil, fmt.Errorf("Dictionary key is not a string")
			}
			idx += n
			val, m, err := decodeBencodeWithConsumed(bencodedString[idx:])
			if err != nil {
				return nil, err
			}
			result[keyStr] = val
			idx += m
		}
		if idx >= len(bencodedString) || bencodedString[idx] != 'e' {
			return nil, fmt.Errorf("Dictionary not terminated properly")
		}
		return result, nil
	} else {
		return "", fmt.Errorf("Only strings, integers, and lists are supported at the moment")
	}
}

// Helper: returns (decoded value, number of chars consumed, error)
func decodeBencodeWithConsumed(bencodedString string) (interface{}, int, error) {
	if len(bencodedString) == 0 {
		return nil, 0, fmt.Errorf("Empty input")
	}
	if unicode.IsDigit(rune(bencodedString[0])) {
		var firstColonIndex int
		for i := 0; i < len(bencodedString); i++ {
			if bencodedString[i] == ':' {
				firstColonIndex = i
				break
			}
		}
		lengthStr := bencodedString[:firstColonIndex]
		length, err := strconv.Atoi(lengthStr)
		if err != nil {
			return nil, 0, err
		}
		start := firstColonIndex + 1
		end := start + length
		if end > len(bencodedString) {
			return nil, 0, fmt.Errorf("String length out of bounds")
		}
		return bencodedString[start:end], end, nil
	} else if bencodedString[0] == 'i' {
		endIdx := 1
		for endIdx < len(bencodedString) && bencodedString[endIdx] != 'e' {
			endIdx++
		}
		if endIdx >= len(bencodedString) {
			return nil, 0, fmt.Errorf("Integer not terminated properly")
		}
		val, err := strconv.Atoi(bencodedString[1:endIdx])
		if err != nil {
			return nil, 0, err
		}
		return val, endIdx + 1, nil
	} else if bencodedString[0] == 'l' {
		var result []interface{}
		idx := 1
		for idx < len(bencodedString) && bencodedString[idx] != 'e' {
			elem, n, err := decodeBencodeWithConsumed(bencodedString[idx:])
			if err != nil {
				return nil, 0, err
			}
			result = append(result, elem)
			idx += n
		}
		if idx >= len(bencodedString) || bencodedString[idx] != 'e' {
			return nil, 0, fmt.Errorf("List not terminated properly")
		}
		return result, idx + 1, nil
	} else if bencodedString[0] == 'd' {
		result := make(map[string]interface{})
		idx := 1
		for idx < len(bencodedString) && bencodedString[idx] != 'e' {
			keyVal, n, err := decodeBencodeWithConsumed(bencodedString[idx:])
			if err != nil {
				return nil, 0, err
			}
			keyStr, ok := keyVal.(string)
			if !ok {
				return nil, 0, fmt.Errorf("Dictionary key is not a string")
			}
			idx += n
			val, m, err := decodeBencodeWithConsumed(bencodedString[idx:])
			if err != nil {
				return nil, 0, err
			}
			result[keyStr] = val
			idx += m
		}
		if idx >= len(bencodedString) || bencodedString[idx] != 'e' {
			return nil, 0, fmt.Errorf("Dictionary not terminated properly")
		}
		return result, idx + 1, nil
	}
	return nil, 0, fmt.Errorf("Unsupported bencode type")
}

func runDecodeCommand(bencodedValue string) {
	decoded, err := decodeBencode(bencodedValue)
	if err != nil {
		fmt.Println(err)
		return
	}
	jsonOutput, _ := json.Marshal(decoded)
	fmt.Println(string(jsonOutput))
}

func runTorrentInfoCommand(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	decoded, err := decodeBencode(string(data))
	if err != nil {
		fmt.Println("Error decoding torrent:", err)
		return
	}
	dict, ok := decoded.(map[string]interface{})
	if !ok {
		fmt.Println("Torrent file is not a dictionary")
		return
	}
	announceVal, ok := dict["announce"]
	if !ok {
		fmt.Println("No announce field found")
		return
	}
	announce, ok := announceVal.(string)
	if !ok {
		fmt.Println("Announce field is not a string")
		return
	}
	infoVal, ok := dict["info"]
	if !ok {
		fmt.Println("No info field found")
		return
	}
	info, ok := infoVal.(map[string]interface{})
	if !ok {
		fmt.Println("Info field is not a dictionary")
		return
	}
	length := 0
	if l, ok := info["length"].(int); ok {
		length = l
	}
	output := map[string]interface{}{
		"announce": announce,
		"length": length,
	}
	jsonOutput, _ := json.Marshal(output)
	fmt.Println(string(jsonOutput))
}

// Bencode encoder for info-hash
func bencode(value interface{}) string {
	switch v := value.(type) {
	case string:
		return strconv.Itoa(len(v)) + ":" + v
	case int:
		return "i" + strconv.Itoa(v) + "e"
	case []interface{}:
		res := "l"
		for _, elem := range v {
			res += bencode(elem)
		}
		res += "e"
		return res
	case map[string]interface{}:
		res := "d"
		// keys must be sorted
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			res += bencode(k)
			res += bencode(v[k])
		}
		res += "e"
		return res
	default:
		return ""
	}
}

func runInfoHashCommand(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	decoded, err := decodeBencode(string(data))
	if err != nil {
		fmt.Println("Error decoding torrent:", err)
		return
	}
	dict, ok := decoded.(map[string]interface{})
	if !ok {
		fmt.Println("Torrent file is not a dictionary")
		return
	}
	info, _ := dict["info"].(map[string]interface{})
	if info == nil {
		fmt.Println("No info dictionary found")
		return
	}
	bencodedInfo := bencode(info)
	hash := sha1.Sum([]byte(bencodedInfo))
	fmt.Printf("%x\n", hash)
}

func runInfoCommand(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	decoded, err := decodeBencode(string(data))
	if err != nil {
		fmt.Println("Error decoding torrent:", err)
		return
	}
	dict, ok := decoded.(map[string]interface{})
	if !ok {
		fmt.Println("Torrent file is not a dictionary")
		return
	}
	announceVal, ok := dict["announce"]
	if !ok {
		fmt.Println("No announce field found")
		return
	}
	announce, ok := announceVal.(string)
	if !ok {
		fmt.Println("Announce field is not a string")
		return
	}
	infoVal, ok := dict["info"]
	if !ok {
		fmt.Println("No info field found")
		return
	}
	info, ok := infoVal.(map[string]interface{})
	if !ok {
		fmt.Println("Info field is not a dictionary")
		return
	}
	length := 0
	if l, ok := info["length"].(int); ok {
		length = l
	}
	pieceLength := 0
	if pl, ok := info["piece length"].(int); ok {
		pieceLength = pl
	}
	piecesVal, ok := info["pieces"]
	if !ok {
		fmt.Println("No pieces field found")
		return
	}
	piecesStr, ok := piecesVal.(string)
	if !ok {
		fmt.Println("Pieces field is not a string")
		return
	}
	pieces := []byte(piecesStr)
	bencodedInfo := bencode(info)
	hash := sha1.Sum([]byte(bencodedInfo))

	fmt.Printf("Tracker URL: %s\n", announce)
	fmt.Printf("Length: %d\n", length)
	fmt.Printf("Info Hash: %x\n", hash)
	fmt.Printf("Piece Length: %d\n", pieceLength)
	fmt.Printf("Piece Hashes:\n")
	for i := 0; i+20 <= len(pieces); i += 20 {
		fmt.Printf("%s\n", pieces[i:i+20])
	}
}

func runPeersCommand(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	decoded, err := decodeBencode(string(data))
	if err != nil {
		fmt.Println("Error decoding torrent:", err)
		return
	}
	dict, ok := decoded.(map[string]interface{})
	if !ok {
		fmt.Println("Torrent file is not a dictionary")
		return
	}
	announceVal, ok := dict["announce"]
	if !ok {
		fmt.Println("No announce field found")
		return
	}
	announce, ok := announceVal.(string)
	if !ok {
		fmt.Println("Announce field is not a string")
		return
	}
	infoVal, ok := dict["info"]
	if !ok {
		fmt.Println("No info field found")
		return
	}
	info, ok := infoVal.(map[string]interface{})
	if !ok {
		fmt.Println("Info field is not a dictionary")
		return
	}
	length := 0
	if l, ok := info["length"].(int); ok {
		length = l
	}
	bencodedInfo := bencode(info)
	infoHash := sha1.Sum([]byte(bencodedInfo))

	// Build tracker URL with query params
	u, err := url.Parse(announce)
	if err != nil {
		fmt.Println("Invalid announce URL:", err)
		return
	}
	params := url.Values{}
	params.Set("info_hash", string(infoHash[:])) // raw bytes
	params.Set("peer_id", "-PC0001-123456789012") // 20 bytes, static for now
	params.Set("port", "6881")
	params.Set("uploaded", "0")
	params.Set("downloaded", "0")
	params.Set("left", strconv.Itoa(length))
	params.Set("compact", "1")

	u.RawQuery = params.Encode()

	resp, err := http.Get(u.String())
	if err != nil {
		fmt.Println("Error making tracker request:", err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading tracker response:", err)
		return
	}
	fmt.Print(string(body))
}

func runHandshakeCommand(filename, peerAddr string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	decoded, err := decodeBencode(string(data))
	if err != nil {
		fmt.Println("Error decoding torrent:", err)
		return
	}
	dict, ok := decoded.(map[string]interface{})
	if !ok {
		fmt.Println("Torrent file is not a dictionary")
		return
	}
	info, _ := dict["info"].(map[string]interface{})
	if info == nil {
		fmt.Println("No info dictionary found")
		return
	}
	bencodedInfo := bencode(info)
	infoHash := sha1.Sum([]byte(bencodedInfo))

	// Generate random 20-byte peer ID
	peerID := make([]byte, 20)
	_, err = rand.Read(peerID)
	if err != nil {
		fmt.Println("Error generating peer ID:", err)
		return
	}

	// Build handshake message
	pstr := "BitTorrent protocol"
	handshake := make([]byte, 49+len(pstr))
	handshake[0] = byte(len(pstr))
	copy(handshake[1:], []byte(pstr))
	copy(handshake[1+len(pstr):1+len(pstr)+8], make([]byte, 8)) // 8 reserved bytes
	copy(handshake[1+len(pstr)+8:], infoHash[:])
	copy(handshake[1+len(pstr)+8+20:], peerID)

	// Connect to peer
	conn, err := net.Dial("tcp", peerAddr)
	if err != nil {
		fmt.Println("Error connecting to peer:", err)
		return
	}
	defer conn.Close()

	// Send handshake
	_, err = conn.Write(handshake)
	if err != nil {
		fmt.Println("Error sending handshake:", err)
		return
	}

	// Receive handshake
	recv := make([]byte, 68)
	n, err := conn.Read(recv)
	if err != nil {
		fmt.Println("Error receiving handshake:", err)
		return
	}
	if n != 68 {
		fmt.Printf("Expected 68 bytes for handshake, got %d\n", n)
		return
	}
	// Extract peer ID from response
	peerIDRecv := recv[48:68]
	fmt.Printf("Peer ID: %x\n", peerIDRecv)
}

func readPeerMessage(conn net.Conn) (id byte, payload []byte, err error) {
	lengthBuf := make([]byte, 4)
	if _, err = io.ReadFull(conn, lengthBuf); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(lengthBuf)
	if length == 0 {
		// keep-alive message
		return 0, nil, nil
	}
	msg := make([]byte, length)
	if _, err = io.ReadFull(conn, msg); err != nil {
		return
	}
	id = msg[0]
	payload = msg[1:]
	return
}

func sendInterested(conn net.Conn) error {
	msg := []byte{0, 0, 0, 1, 2} // length=1, id=2
	_, err := conn.Write(msg)
	return err
}

func sendRequest(conn net.Conn, index, begin, length int) error {
	msg := make([]byte, 17)
	binary.BigEndian.PutUint32(msg[0:4], 13) // length
	msg[4] = 6 // id
	binary.BigEndian.PutUint32(msg[5:9], uint32(index))
	binary.BigEndian.PutUint32(msg[9:13], uint32(begin))
	binary.BigEndian.PutUint32(msg[13:17], uint32(length))
	_, err := conn.Write(msg)
	return err
}

func runDownloadPieceCommand(filename, peerAddr string, pieceIndex int) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	decoded, err := decodeBencode(string(data))
	if err != nil {
		fmt.Println("Error decoding torrent:", err)
		return
	}
	dict, ok := decoded.(map[string]interface{})
	if !ok {
		fmt.Println("Torrent file is not a dictionary")
		return
	}
	infoVal, ok := dict["info"]
	if !ok {
		fmt.Println("No info field found")
		return
	}
	info, ok := infoVal.(map[string]interface{})
	if !ok {
		fmt.Println("Info field is not a dictionary")
		return
	}
	pieceLength := 0
	if pl, ok := info["piece length"].(int); ok {
		pieceLength = pl
	} else {
		fmt.Println("No piece length found")
		return
	}
	piecesVal, ok := info["pieces"]
	if !ok {
		fmt.Println("No pieces field found")
		return
	}
	piecesStr, ok := piecesVal.(string)
	if !ok {
		fmt.Println("Pieces field is not a string")
		return
	}
	pieces := []byte(piecesStr)
	bencodedInfo := bencode(info)
	infoHash := sha1.Sum([]byte(bencodedInfo))

	// Generate random 20-byte peer ID
	peerID := make([]byte, 20)
	_, err = rand.Read(peerID)
	if err != nil {
		fmt.Println("Error generating peer ID:", err)
		return
	}

	// Build handshake message
	pstr := "BitTorrent protocol"
	handshake := make([]byte, 49+len(pstr))
	handshake[0] = byte(len(pstr))
	copy(handshake[1:], []byte(pstr))
	copy(handshake[1+len(pstr):1+len(pstr)+8], make([]byte, 8)) // 8 reserved bytes
	copy(handshake[1+len(pstr)+8:], infoHash[:])
	copy(handshake[1+len(pstr)+8+20:], peerID)

	// Connect to peer
	conn, err := net.Dial("tcp", peerAddr)
	if err != nil {
		fmt.Println("Error connecting to peer:", err)
		return
	}
	defer conn.Close()

	// Send handshake
	_, err = conn.Write(handshake)
	if err != nil {
		fmt.Println("Error sending handshake:", err)
		return
	}

	// Receive handshake
	recv := make([]byte, 68)
	n, err := io.ReadFull(conn, recv)
	if err != nil || n != 68 {
		fmt.Println("Error receiving handshake or wrong length:", err)
		return
	}

	// Wait for bitfield (id=5)
	for {
		id, _, err := readPeerMessage(conn)
		if err != nil {
			fmt.Println("Error reading peer message:", err)
			return
		}
		if id == 5 {
			break
		}
	}

	// Send interested
	if err := sendInterested(conn); err != nil {
		fmt.Println("Error sending interested message:", err)
		return
	}

	// Wait for unchoke (id=1)
	for {
		id, _, err := readPeerMessage(conn)
		if err != nil {
			fmt.Println("Error reading peer message:", err)
			return
		}
		if id == 1 {
			break
		}
	}

	// Request blocks for the piece
	blockSize := 16 * 1024
	totalBlocks := (pieceLength + blockSize - 1) / blockSize
	pieceData := make([]byte, 0, pieceLength)
	for block := 0; block < totalBlocks; block++ {
		begin := block * blockSize
		length := blockSize
		if begin+length > pieceLength {
			length = pieceLength - begin
		}
		if err := sendRequest(conn, pieceIndex, begin, length); err != nil {
			fmt.Println("Error sending request message:", err)
			return
		}
	}

	// Receive piece blocks
	received := 0
	blocks := make(map[int][]byte)
	for received < pieceLength {
		id, payload, err := readPeerMessage(conn)
		if err != nil {
			fmt.Println("Error reading piece message:", err)
			return
		}
		if id == 7 {
			if len(payload) < 8 {
				fmt.Println("Piece message payload too short")
				return
			}
			idx := int(binary.BigEndian.Uint32(payload[0:4]))
			begin := int(binary.BigEndian.Uint32(payload[4:8]))
			block := payload[8:]
			if idx == pieceIndex {
				blocks[begin] = block
				received += len(block)
			}
		}
	}
	// Reassemble piece
	piece := make([]byte, pieceLength)
	for begin, block := range blocks {
		copy(piece[begin:], block)
	}
	// Check hash
	if pieceIndex*20+20 > len(pieces) {
		fmt.Println("Piece index out of range for hash check")
		return
	}
	expectedHash := pieces[pieceIndex*20 : pieceIndex*20+20]
	actualHash := sha1.Sum(piece)
	if !equalHashes(expectedHash, actualHash[:]) {
		fmt.Println("Piece hash does not match!")
	} else {
		fmt.Println("Piece downloaded and hash verified!")
	}
}

func equalHashes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func runDownloadCommand(outputFile, filename, peerAddr string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	decoded, err := decodeBencode(string(data))
	if err != nil {
		fmt.Println("Error decoding torrent:", err)
		return
	}
	dict, ok := decoded.(map[string]interface{})
	if !ok {
		fmt.Println("Torrent file is not a dictionary")
		return
	}
	infoVal, ok := dict["info"]
	if !ok {
		fmt.Println("No info field found")
		return
	}
	info, ok := infoVal.(map[string]interface{})
	if !ok {
		fmt.Println("Info field is not a dictionary")
		return
	}
	pieceLength, ok := info["piece length"].(int)
	if !ok {
		fmt.Println("No piece length found")
		return
	}
	length, ok := info["length"].(int)
	if !ok {
		fmt.Println("No file length found")
		return
	}
	piecesVal, ok := info["pieces"]
	if !ok {
		fmt.Println("No pieces field found")
		return
	}
	piecesStr, ok := piecesVal.(string)
	if !ok {
		fmt.Println("Pieces field is not a string")
		return
	}
	pieces := []byte(piecesStr)
	bencodedInfo := bencode(info)
	infoHash := sha1.Sum([]byte(bencodedInfo))

	// Generate random 20-byte peer ID
	peerID := make([]byte, 20)
	_, err = rand.Read(peerID)
	if err != nil {
		fmt.Println("Error generating peer ID:", err)
		return
	}

	// Build handshake message
	pstr := "BitTorrent protocol"
	handshake := make([]byte, 49+len(pstr))
	handshake[0] = byte(len(pstr))
	copy(handshake[1:], []byte(pstr))
	copy(handshake[1+len(pstr):1+len(pstr)+8], make([]byte, 8)) // 8 reserved bytes
	copy(handshake[1+len(pstr)+8:], infoHash[:])
	copy(handshake[1+len(pstr)+8+20:], peerID)

	// Connect to peer
	conn, err := net.Dial("tcp", peerAddr)
	if err != nil {
		fmt.Println("Error connecting to peer:", err)
		return
	}
	defer conn.Close()

	// Send handshake
	_, err = conn.Write(handshake)
	if err != nil {
		fmt.Println("Error sending handshake:", err)
		return
	}

	// Receive handshake
	recv := make([]byte, 68)
	n, err := io.ReadFull(conn, recv)
	if err != nil || n != 68 {
		fmt.Println("Error receiving handshake or wrong length:", err)
		return
	}

	// Wait for bitfield (id=5)
	for {
		id, _, err := readPeerMessage(conn)
		if err != nil {
			fmt.Println("Error reading peer message:", err)
			return
		}
		if id == 5 {
			break
		}
	}

	// Send interested
	if err := sendInterested(conn); err != nil {
		fmt.Println("Error sending interested message:", err)
		return
	}

	// Wait for unchoke (id=1)
	for {
		id, _, err := readPeerMessage(conn)
		if err != nil {
			fmt.Println("Error reading peer message:", err)
			return
		}
		if id == 1 {
			break
		}
	}

	numPieces := len(pieces) / 20
	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer file.Close()

	blockSize := 16 * 1024
	for pieceIndex := 0; pieceIndex < numPieces; pieceIndex++ {
		// Calculate this piece's length (last piece may be shorter)
		thisPieceLen := pieceLength
		if pieceIndex == numPieces-1 {
			thisPieceLen = length - (pieceLength * (numPieces - 1))
		}
		// Request all blocks for this piece
		totalBlocks := (thisPieceLen + blockSize - 1) / blockSize
		for block := 0; block < totalBlocks; block++ {
			begin := block * blockSize
			blen := blockSize
			if begin+blen > thisPieceLen {
				blen = thisPieceLen - begin
			}
			if err := sendRequest(conn, pieceIndex, begin, blen); err != nil {
				fmt.Printf("Error sending request for piece %d block %d: %v\n", pieceIndex, block, err)
				return
			}
		}
		// Receive all blocks for this piece
		received := 0
		blocks := make(map[int][]byte)
		for received < thisPieceLen {
			id, payload, err := readPeerMessage(conn)
			if err != nil {
				fmt.Printf("Error reading piece %d: %v\n", pieceIndex, err)
				return
			}
			if id == 7 {
				if len(payload) < 8 {
					fmt.Printf("Piece %d message payload too short\n", pieceIndex)
					return
				}
				idx := int(binary.BigEndian.Uint32(payload[0:4]))
				begin := int(binary.BigEndian.Uint32(payload[4:8]))
				block := payload[8:]
				if idx == pieceIndex {
					blocks[begin] = block
					received += len(block)
				}
			}
		}
		// Reassemble piece
		piece := make([]byte, thisPieceLen)
		for begin, block := range blocks {
			copy(piece[begin:], block)
		}
		// Check hash
		if pieceIndex*20+20 > len(pieces) {
			fmt.Printf("Piece %d index out of range for hash check\n", pieceIndex)
			return
		}
		expectedHash := pieces[pieceIndex*20 : pieceIndex*20+20]
		actualHash := sha1.Sum(piece)
		if !equalHashes(expectedHash, actualHash[:]) {
			fmt.Printf("Piece %d hash does not match!\n", pieceIndex)
			return
		}
		// Write to file
		_, err := file.WriteAt(piece, int64(pieceIndex*pieceLength))
		if err != nil {
			fmt.Printf("Error writing piece %d to file: %v\n", pieceIndex, err)
			return
		}
		fmt.Printf("Downloaded and verified piece %d/%d\n", pieceIndex+1, numPieces)
	}
	fmt.Println("Download complete!")
}

func main() {
	fmt.Fprintln(os.Stderr, "Logs from your program will appear here!")

	if len(os.Args) < 2 {
		fmt.Println("No command provided")
		os.Exit(1)
	}
	command := os.Args[1]

	switch command {
	case "decode":
		if len(os.Args) < 3 {
			fmt.Println("Usage: decode <bencoded-value>")
			return
		}
		runDecodeCommand(os.Args[2])
	case "torrent-info":
		if len(os.Args) < 3 {
			fmt.Println("Usage: torrent-info <torrent-file>")
			return
		}
		runTorrentInfoCommand(os.Args[2])
	case "info-hash":
		if len(os.Args) < 3 {
			fmt.Println("Usage: info-hash <torrent-file>")
			return
		}
		runInfoHashCommand(os.Args[2])
	case "info":
		if len(os.Args) < 3 {
			fmt.Println("Usage: info <torrent-file>")
			return
		}
		runInfoCommand(os.Args[2])
	case "peers":
		if len(os.Args) < 3 {
			fmt.Println("Usage: peers <torrent-file>")
			return
		}
		runPeersCommand(os.Args[2])
	case "handshake":
		if len(os.Args) < 4 {
			fmt.Println("Usage: handshake <torrent-file> <peer_ip>:<peer_port>")
			return
		}
		runHandshakeCommand(os.Args[2], os.Args[3])
	case "download-piece":
		if len(os.Args) < 5 {
			fmt.Println("Usage: download-piece <torrent-file> <peer_ip>:<peer_port> <piece_index>")
			return
		}
		pieceIndex, err := strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Println("Invalid piece index")
			return
		}
		runDownloadPieceCommand(os.Args[2], os.Args[3], pieceIndex)
	case "download":
		if len(os.Args) < 6 || os.Args[2] != "-o" {
			fmt.Println("Usage: download -o <output-file> <torrent-file> <peer_ip>:<peer_port>")
			return
		}
		runDownloadCommand(os.Args[3], os.Args[4], os.Args[5])
	default:
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
