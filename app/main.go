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
	} else if rune(bencodedString[0])=='i'{
		return strconv.Atoi(bencodedString[1:len(bencodedString)-1])
	} else if bencodedString[0] == 'l' {
		// decode list
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
		// decode dictionary
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
	announce, _ := dict["announce"].(string)
	info, _ := dict["info"].(map[string]interface{})
	length := 0
	if info != nil {
		if l, ok := info["length"].(int); ok {
			length = l
		}
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
	announce, _ := dict["announce"].(string)
	info, _ := dict["info"].(map[string]interface{})
	if info == nil {
		fmt.Println("No info dictionary found")
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
	pieces, _ := info["pieces"].(string)
	bencodedInfo := bencode(info)
	hash := sha1.Sum([]byte(bencodedInfo))

	fmt.Printf("Tracker URL: %s\n", announce)
	fmt.Printf("Length: %d\n", length)
	fmt.Printf("Info Hash: %x\n", hash)
	fmt.Printf("Piece Length: %d\n", pieceLength)
	fmt.Printf("Piece Hashes:\n")
	for i := 0; i+20 <= len(pieces); i += 20 {
		fmt.Printf("%x\n", pieces[i:i+20])
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
	announce, _ := dict["announce"].(string)
	info, _ := dict["info"].(map[string]interface{})
	if info == nil {
		fmt.Println("No info dictionary found")
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
	params.Set("info_hash", string(infoHash[:])) // will be URL-encoded below
	params.Set("peer_id", "-PC0001-123456789012") // 20 bytes, static for now
	params.Set("port", "6881")
	params.Set("uploaded", "0")
	params.Set("downloaded", "0")
	params.Set("left", strconv.Itoa(length))
	params.Set("compact", "1")

	// Manually URL-encode info_hash as raw bytes
	q := u.Query()
	for k, v := range params {
		if k == "info_hash" {
			q.Set(k, url.QueryEscape(string(infoHash[:])))
		} else {
			q.Set(k, v[0])
		}
	}
	u.RawQuery = q.Encode()

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
	default:
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
