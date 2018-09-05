package util
// Finds the IP address of this machine.
// Based on https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
import (
    "net"
    "errors"
    "fmt"
    "io/ioutil"
    "encoding/json"
    "net/http"
    "strings"
    "crypto/aes"
    "crypto/cipher"
    "sync"
    "strconv"
);

func PutReq(url string, msg string, header_vals map[string]string) (map[string]string, bool) {
    // Create client object to send requests
    client := &http.Client{}

    // Create the put request
    req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(msg))

    // Add header vals if any
    for key, val := range header_vals {
        req.Header.Add(key, val)
    }

    // Fire the put request and check for errors in the request
    blank_dat := make(map[string]string) // for error before dat is created
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("Error with put request to " + url + " | meg: " + msg)
        return blank_dat, false
    }

    // Decode the response message from discovery server and print it, if bad terminate
    dat := DecodeResp(resp)
    if resp.StatusCode != 200 {
        fmt.Println("Error with decoding resp")
        return dat, false
    }

    return dat, true // return true is successful
}

func MyIP() (string, error) {
    ifaces, _ := net.Interfaces()
    var ip net.IP
    // handle err
    for _, i := range ifaces {
        addrs, _ := i.Addrs()
        // handle err
        for _, addr := range addrs {
            switch v := addr.(type) {
            case *net.IPNet:
                    ip = v.IP
            case *net.IPAddr:
                    ip = v.IP
            }
            if ip.IsGlobalUnicast() {
                return ip.String(), nil
            }
        }
    }
    return "", errors.New("No valid IP address detected")
}

func CheckArgs(args []string, parameters string, arg_count int) bool {
    // Check if argument count is correct
    if len(args) < arg_count{
        fmt.Println("Needs more args!!")
        fmt.Println(parameters)
        return true
    }
    if len(args) > arg_count{
        fmt.Println("Too many args!!")
        fmt.Println(parameters)
        return true
    }

    return false
}

func DecodeResp(resp *http.Response) map[string]string {
    // decodes the c.JSON response into dict
    var dat map[string]string
    defer resp.Body.Close()
    bodyBytes, _ := ioutil.ReadAll(resp.Body)
    json.Unmarshal(bodyBytes, &dat)
    return dat
}

func EncodeStringSlice(strslice []string) string{
    // Go from []string -> comma seperated string
    str := make([]string, 0)
    for _, el := range strslice{
        str = append(str, el)
    }
    new_strslice := strings.Join(str, ",")
    return new_strslice
}

func DecodeString(str string) []string{
    // Go from comma seperated string -> []string
    return strings.Split(str, ",")
}


// Encrypion functions
const AES_BLOCK_SIZE int = 16
const PADDING_SYMBOL byte = ' '

func makeCipher(key string) (theCipher cipher.Block, err error){
    // Force key to be proper size.
    for len(key) < AES_BLOCK_SIZE{
        key = key + " " + key
    }
    if len(key) > AES_BLOCK_SIZE{
        key = key[0:AES_BLOCK_SIZE]
    }
    theCipher, err = aes.NewCipher([]byte(key))
    return
}

func SimpleAESEncode(text, key string) (result string, err error) {
    cipher, err := makeCipher(key)
    if err != nil {
        return
    }
    result = ""
    // Continue crunching numbers until you have resolved the entire text.
    for len(text) > 0 {
        // Make sure this is long enough to be encrypted.
        for len(text) < AES_BLOCK_SIZE{
            text += string(PADDING_SYMBOL)
        }
        next_block := text[:AES_BLOCK_SIZE]
        text = text[AES_BLOCK_SIZE:]
        // Convert this block.
        result_block := make([]byte, AES_BLOCK_SIZE)
        cipher.Encrypt(result_block, []byte(next_block))
        result += string(result_block)
    }
    result = SuperSafeEncode(result)
    return
}

func SimpleAESDecode(text, key string) (result string, err error) {
    text, err = SuperSafeDecode(text)
    if err != nil {
        return
    }
    if len(text) % AES_BLOCK_SIZE != 0{
        err = errors.New("ciphertext size must be multiple of " + strconv.Itoa(AES_BLOCK_SIZE))
    }
    cipher, err := makeCipher(key)
    if err != nil {
        return
    }
    result = ""
    // Continue crunching numbers until you have resolved the entire text.
    for len(text) > 0 {
        next_block := text[0:AES_BLOCK_SIZE]
        text = text[AES_BLOCK_SIZE:]
        // Convert this block.
        result_block := make([]byte, AES_BLOCK_SIZE)
        cipher.Decrypt(result_block, []byte(next_block))
        result += string(result_block)
    }
    // Remove padding if present.
    for len(result) > 0 && result[len(result)-1] == PADDING_SYMBOL{
        result = result[:len(result)-1]
    }
    return
}

func StringInSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}

func MapAllTrue(a map[string]bool, map_mutex *sync.Mutex) bool{
    map_mutex.Lock()
    for _, v := range a {
        if !v {
            map_mutex.Unlock()
            return false
        }
    }
    map_mutex.Unlock()
    return true
}

func SuperSafeEncode(a string) string{
    input_bytes := []byte(a)
    result := make([]string, 0)
    for _, c := range input_bytes{
        result = append(result, strconv.Itoa(int(c)))
    }
    return strings.Join(result, "d")
}

func SuperSafeDecode(a string) (string, error){
    input_nums := strings.Split(a, "d")
    result := make([]byte, 0)
    for _, c := range input_nums{
        num, err := strconv.Atoi(c)
        if err != nil{
            return "", err
        }
        result = append(result, byte(num))
    }
    return string(result), nil
}
