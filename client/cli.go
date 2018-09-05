package main

import(
    "os"
    "fmt"
    "net/http"
    "bufio"
    "strings"
    "github.com/gin-gonic/gin"
    "go-wechat-hw1-team04/util"
    "encoding/json"
    "time"
    "strconv"
    "sync"
)
// Structs needed for vector clocks and queued up messages
type VectorClock map[string]uint64
type MSG struct{
    Id string
    Username string
    // timestamp VectorClock
    Timestamp uint64 // THIS IS SEQUENCE NUMBER
    Msg string
}

func (this MSG) String() string{
    speaker_message_dec, _ := util.SimpleAESDecode(this.Msg, PARAMETERS["channel_pw"])
    return this.Id + ": " + speaker_message_dec
}

type Chat_History []MSG

func (this Chat_History) String() string{
    result := ""
    for _, msg := range this {
        result += msg.String() + "\n"
    }
    return result
}

var PENDING_MESSAGE_VC VectorClock // For storing the queued up message
var VECTOR_CLOCK VectorClock // Internal vector clock for this client
var CHAT_HISTORY Chat_History // Records all non-pending messages

// Global mutex's
var CLOCK_LOCK = &sync.Mutex{} // Create vector clock mutex
var CHAT_HIST_LOCK = &sync.Mutex{} // Create chat history mutex

func (self VectorClock) happensBefore(other VectorClock) bool{
    at_least_one_of_mine_are_better := false
    for k, other_value := range other{
        my_value, i_have_k := self[k]
        // If I don't have this field, I can't prove I'm earlier than you.
        if !i_have_k{
            return false
        }
        // I can't claim I came before you if you have a field that's earlier than mine.
        if my_value > other_value{
            return false
        }
        // If you have a field that's greater than mine, I might be before you!
        if other_value > my_value{
            at_least_one_of_mine_are_better = true
        }
    }
    // If I found that at least one of my fields where better than yours by now, I win!
    return at_least_one_of_mine_are_better
}

// Parameters for arg check, and timeout
const ARG_COUNT int = 7
const PARAMETERS_SCHEMA string = "./cli [username] [channel] [channel_pw] [join] [server_IP]:[server_port] [client_port]"
const DEATH_TIME_OUT float64 = 3000
const PING_PERIOD float64 = 100

var PARAMETERS map[string]string // for storing client input parameters
var IP_USERS map[string]string // ip:user map of strings, holds current ppl in conv

func main() {
    // Check if the number of parameters is correct and return if not
    args := os.Args
    if util.CheckArgs(args, PARAMETERS_SCHEMA, ARG_COUNT) {return}

    // Assign args to variables and print them out
    PARAMETERS = make(map[string]string)
    PARAMETERS["username"] = args[1] // unique user id (per channel id)
    PARAMETERS["channel"] = args[2] // unique chat channel id
    PARAMETERS["channel_pw"] = args[3] // password to join
    PARAMETERS["join"] = args[4] // T/F true false if joining
    PARAMETERS["server_addr"] = args[5] // IP:PORT
    PARAMETERS["client_port"] = args[6] // client PORT
    client_ip, err := util.MyIP()
    if err != nil {
        fmt.Println("OH NO! I can't figure out your ip address! CRASHING!!! :(")
        return
    }
    PARAMETERS["client_ip"] = client_ip
    fmt.Println("Your parameters:\n", PARAMETERS)

    // Initialize the vector clock, message buffer, and IP_USERS
    VECTOR_CLOCK = make(map[string]uint64)
    PENDING_MESSAGE_VC = nil
    IP_USERS = make(map[string]string)
    CHAT_HISTORY = make(Chat_History, 0)

    // Start server to listen for IP of session from discovery server and for other clients
    go start_server()

    // Determine if creating a new channel or joining an existing one
    var dat map[string]string // declare both since in if/else so inside that scope
    var success bool
    if strings.Compare(PARAMETERS["join"], "T") == 0 {
        // Tell discovery server you JOIN wanna chat, send IP + pw as IP,pw
        dat, success = util.PutReq(
            "http://" + PARAMETERS["server_addr"] + "/channels/" + PARAMETERS["channel"] + "/join/" + PARAMETERS["username"],
            PARAMETERS["client_ip"] + ":" + PARAMETERS["client_port"] + "," + PARAMETERS["channel_pw"],
            make(map[string]string))
    } else {
        // Tell discovery server you CREATE a new chat (and then join it), send IP + pw as IP,pw
        dat, success = util.PutReq(
            "http://" + PARAMETERS["server_addr"] + "/channels/" + PARAMETERS["channel"] + "/create/" + PARAMETERS["username"],
            PARAMETERS["client_ip"] + ":" + PARAMETERS["client_port"] + "," + PARAMETERS["channel_pw"],
            make(map[string]string))

    }
    if !success { // Error check
        fmt.Println("Error in joining, aborting!")
        return
    }

    // If successful, take in the returned list of ips + users -> store into IP_USERS
    all_ips_string := strings.Split(dat["all_ips_string"], ",")
    all_users_string := strings.Split(dat["all_users_string"], ",")
    for i, _ := range all_ips_string {
        IP_USERS[all_ips_string[i]] = all_users_string[i]
    }

    // If you joined and did not create, broadcast to your peers that you are here!
    // Marshal the updated IP_USERS to send to others in the channel
    ip_users_marsh, err := json.Marshal(IP_USERS)

    if strings.Compare(PARAMETERS["join"], "T") == 0 {

        // Create lock for concurrent updating of the chat log
        for ip, _ := range IP_USERS {
            go broadcast_entry_to_conv(ip, ip_users_marsh)
        }
    }

    // Wait a bit for us to settle on a chat history.
    fmt.Println("Waiting for chat logs...")
    time.Sleep(time.Duration(DEATH_TIME_OUT) * time.Millisecond)

    // Dump chat history
    fmt.Println(CHAT_HISTORY)

    // Start chatting!
    request_input()
    for { // chat until killed
        reader := bufio.NewReader(os.Stdin)
        text, _ := reader.ReadString('\n')
        send_msg(text)
        request_input()
    }
}

func start_server() {
    gin.SetMode(gin.ReleaseMode)
    r := gin.New()
    r.Use(gin.Recovery())

    // define all protocols to listen for
    r.PUT("/channels/" + PARAMETERS["channel"] + "/messages", hear_msg) // for recieving messages
    r.PUT("/receive_other_ips", receive_other_ips) // for recieving updated IP list from new peer
    r.GET("/receive_mic_check", receive_mic_check) // for requests to talk
    r.PUT("/receive_chat_hist", receive_chat_hist) // for get up to date chat hist
    r.GET("/get_history/:room_id", get_history) // Ask for an unencrypted chat history.  (Would not be in REAL application)

    // start the server ono the given port
    r.Run(":" + PARAMETERS["client_port"])
}

func request_input() {
    fmt.Print(PARAMETERS["username"] + ": ")
}

func get_history(c *gin.Context) {
    if c.Param("room_id") == PARAMETERS["channel"] {
        // Build up messages.
        c.JSON(200, CHAT_HISTORY.String())
    } else {
        // We aren't on this channel!
        c.JSON(404, "I'm not on that channel!")
    }
}

func receive_chat_hist(c *gin.Context) {
    updateVectorClockBasedOnString(c.GetHeader("vectorclock"))
    chat_hist_string := c.GetHeader("chat_hist_marsh")


    // Unmarshal chat history
    incoming_chat_hist := make(Chat_History, 0)
    err := json.Unmarshal([]byte(chat_hist_string), &incoming_chat_hist)
    if err != nil {
        fmt.Println("Error unmarshalling chat history")
    }

    // If received chat_history longer than current, take it as legit
    CHAT_HIST_LOCK.Lock()
    if len(incoming_chat_hist) > len(CHAT_HISTORY) {
        CHAT_HISTORY = incoming_chat_hist
    }
    CHAT_HIST_LOCK.Unlock()

    return
}

func broadcast_entry_to_conv(ip string, ip_users_marsh []byte) {
    // Send marshaled IP_USERS to other clients in a put request
    header_vals := make(map[string]string)
    header_vals["broadcaster_ip"] = PARAMETERS["client_ip"] + ":" + PARAMETERS["client_port"]
    header_vals["vectorclock"] = currentVectorClockTimeString()
    _, success := util.PutReq(
        "http://" + ip + "/receive_other_ips",
        string(ip_users_marsh),
        header_vals)
    if !success { // Error check
        fmt.Println("Error in broadcasting entry to channel")
    }

    return
}

func receive_other_ips(c *gin.Context) {
    updateVectorClockBasedOnString(c.GetHeader("vectorclock"))
    // Get the raw IP_USERS from sender
    ip_users_string, err := c.GetRawData()
    if err != nil{ // error check
        fmt.Println("Error receiving new ips")
        fmt.Println(err)
        return
    }

    // Unmarhsal ip_users_string (should be map[string]string <-> ip:user)
    var incoming_ip_users map[string]string
    err = json.Unmarshal(ip_users_string, &incoming_ip_users)
    if err != nil{
        fmt.Println("Error with unmarshalling incoming IP_USERS")
        fmt.Println(err)
        return
    }
    // If successful, replace local IP_USERS
    IP_USERS = incoming_ip_users

    // Update VECTOR CLOCK, might be missing entries!
    CLOCK_LOCK.Lock()
    for ip, _ := range IP_USERS{
        if _, ok := VECTOR_CLOCK[ip]; !ok{
            // Oops!  We don't have an entry for this IP yet!
            VECTOR_CLOCK[ip] = 0
        }
    }
    CLOCK_LOCK.Unlock()

    // return the chat history to new entrant, first marshal it
    chat_hist_marsh, err := json.Marshal(CHAT_HISTORY)

    // Create client object to send requests
    client := &http.Client{}

    // Create the put request
    req, _ := http.NewRequest(
        http.MethodPut,
        "http://" + c.GetHeader("broadcaster_ip") + "/receive_chat_hist",
        strings.NewReader(""))

    req.Header.Add("chat_hist_marsh", string(chat_hist_marsh))
    req.Header.Add("vectorclock", currentVectorClockTimeString())

    // Fire the put request and check for errors in the request
    _, err = client.Do(req)
    if err != nil {
        fmt.Println("Error in sending marshaled chat history")
    }

    return
}

func send_mic_check(receiver string, vector_clock VectorClock, has_confirmed * map[string]bool, has_confirmed_mutex *sync.Mutex) {
    start_time := time.Now()
    // We will want to send our message's vector clock for comparison
    stamp_string, err := json.Marshal(vector_clock)
    if err != nil {
        fmt.Println("Could not marshal VECTOR_CLOCK")
        fmt.Println(err)
        return
    }
    // Ask IP for approval.
    client := &http.Client{}
    // Keep trying until they give it!
    for{
        if time.Since(start_time).Seconds()*1000 > DEATH_TIME_OUT{
            // Our time has run out!  We're talking to a dead client, get out of here!
            return
        }
        req, err := http.NewRequest(
            http.MethodGet,
            "http://" + receiver + "/receive_mic_check",
            strings.NewReader(string(stamp_string)))
        if err == nil {
            req.Header.Add("vectorclock",currentVectorClockTimeString())
            req.Header.Add("address", PARAMETERS["client_ip"]+":"+PARAMETERS["client_port"])
            resp, err := client.Do(req)
            if err == nil {
                if resp.StatusCode == 200{
                    // Take has_confirmed lock
                    has_confirmed_mutex.Lock()

                    // This IP has confirmed!
                    (*has_confirmed)[receiver] = true

                    // Release has_confirmed lock
                    has_confirmed_mutex.Unlock()
                    return
                }
            }
        }
        time.Sleep(time.Duration(PING_PERIOD) * time.Millisecond)
    }
}

func receive_mic_check(c *gin.Context) {
    updateVectorClockBasedOnString(c.GetHeader("vectorclock"))
    // Unwrap message
    clock_text, err := c.GetRawData()
    if err != nil{
        fmt.Println("Heard faulty mic check:")
        fmt.Println(err)
        c.JSON(401, gin.H{"message":"401 -> UNAUTHORIZED"})
        return
    }
    var incomming_vector_clock VectorClock
    err = json.Unmarshal(clock_text, &incomming_vector_clock)
    if err != nil{
        fmt.Println("Mic check didn't deliver vector clock:")
        fmt.Println(err)
        c.JSON(401, gin.H{"message":"401 -> UNAUTHORIZED"})
        return
    }

    // If I have no pending message, I give you permission to speak!
    if PENDING_MESSAGE_VC == nil {
        c.JSON(200, gin.H{"message":"200 -> OK"})
        return
    }
    // If your message's vector clock comes before mine, you may speak.
    if incomming_vector_clock.happensBefore(PENDING_MESSAGE_VC){
        c.JSON(200, gin.H{"message":"200 -> OK"})
        return
    }
    // If my message's vector clock comes before yours, I do not give you permission to speak.
    if PENDING_MESSAGE_VC.happensBefore(incomming_vector_clock){
        c.JSON(401, gin.H{"message":"401 -> UNAUTHORIZED"})
        return
    }
    // If our vector clocks tie but your IP address has priority over mine, you may speak.
    if strings.Compare(c.GetHeader("source"), PARAMETERS["client_ip"]+":"+PARAMETERS["client_port"]) >= 0 {
        c.JSON(200, gin.H{"message":"200 -> OK"})
        return
    }
}

func send_msg(text string) {
    // Time has advanced.
    updateMyVectorClockEntry()

    // Encrypt the message with channel password
    my_message_enc, _ := util.SimpleAESEncode(text, PARAMETERS["channel_pw"])

    // Store this message in buffer as something you're trying to send, send clone
    vector_clock_clone := make(map[string]uint64)
    CLOCK_LOCK.Lock()
    for ip, val := range VECTOR_CLOCK{
        vector_clock_clone[ip] = val
    }
    CLOCK_LOCK.Unlock()
    PENDING_MESSAGE_VC = vector_clock_clone

    // Ask all clients for permission to release.  Repeat until they accept or are considered dead
    has_confirmed := make(map[string]bool)
    for ip, _ := range IP_USERS {
        has_confirmed[ip] = false
    }

    // Create lock for concurrent updating of has_confirmed boolean map
    var has_confirmed_mutex = &sync.Mutex{}

    for ip, _ := range IP_USERS {
        go send_mic_check(ip, PENDING_MESSAGE_VC, &has_confirmed, has_confirmed_mutex) // has_confirmed_mutex important since concurrent!
    }

    start_time := time.Now()
    for !util.MapAllTrue(has_confirmed, has_confirmed_mutex) { // while not all in convo have responded...
        // Waiting for responses...
        if time.Since(start_time).Seconds()*1000 > DEATH_TIME_OUT{
            // Anyone who didn't okay our message is dead to us and tell discovery server to update
            mark_as_dead(has_confirmed)
            break
        }
    }

    // For everyone who has approved, send them an encrypted message
    clock_string, err := json.Marshal(VECTOR_CLOCK)
    if err != nil{
        fmt.Println("Error packaging vector clock:")
        fmt.Println(err)
        return
    }

    // We've officially found our place in the sequence!
    //sequence_number := len(CHAT_HISTORY)
    sequence_number := strconv.Itoa(len(CHAT_HISTORY))

    // Create header vals to send as well including vector clock
    header_vals := make(map[string]string)
    header_vals["senders_clock"] = string(clock_string)
    header_vals["sequence_number"] = sequence_number
    header_vals["type"] = "MSG"
    header_vals["username"] = PARAMETERS["username"]
    header_vals["ip"] = PARAMETERS["client_ip"] + ":" + PARAMETERS["client_port"]
    header_vals["msg_id"] = PARAMETERS["username"] + "_" + sequence_number
    header_vals["vectorclock"] = currentVectorClockTimeString()
    // Tell everyone the clever thing you said.
    for target_address, _ := range IP_USERS { // Send to all ip's the message including self
        _, success := util.PutReq(
            "http://" + target_address + "/channels/" + PARAMETERS["channel"] + "/messages",
            my_message_enc,
            header_vals)
        if !success {
            fmt.Println("Error in telling PUT request to send your message")
        }
    }

    // No more pending message now
    PENDING_MESSAGE_VC = nil

    return
}

func hear_msg(c *gin.Context){
    updateVectorClockBasedOnString(c.GetHeader("vectorclock"))
    // Reject user if they are not in this conversation
    if IP_USERS[c.GetHeader("ip")] == string(0) {
        c.JSON(401, gin.H{"message":"401 -> UNAUTHORIZED (user not in channel)"})
        return
    }

    // If user valid, get their message
    encrypted_msg, err := c.GetRawData()
    if err != nil{
        fmt.Println("Failed to hear incomming message text")
        fmt.Println(err)
        return
    }

    // Get vector clock of sender.
    var senders_clock VectorClock
    json.Unmarshal([]byte(c.GetHeader("senders_clock")), &senders_clock)

    // Update local vector clock
    updateVectorClockBasedOn(senders_clock)

    received_sequence_number, err := strconv.Atoi(c.GetHeader("sequence_number"))
    if err != nil{
        fmt.Println("Failed to hear incomming message sequence number")
        fmt.Println(err)
        return
    }
    received_msg := MSG{
        c.GetHeader("msg_id"),
        c.GetHeader("username"),
        uint64(received_sequence_number),
        string(encrypted_msg),
    }
    CHAT_HISTORY = append(CHAT_HISTORY, received_msg)

    fmt.Println("\t" + received_msg.String())

    // Send back success
    c.JSON(200, gin.H{"message":"200 -> OK"})
    return
}

func mark_as_dead(has_confirmed map[string]bool) {
    // anyone that is still false in has_confirmed is a dead ip now (timed out)
    temp_ip_users := make(map[string]string)
    for ip, not_dead := range has_confirmed {
        if not_dead { // if not dead, add to new IP_USERS slice
            temp_ip_users[ip] = IP_USERS[ip]
        }
    }
    IP_USERS = temp_ip_users // replace local IP_USERS with new non_dead users

    // Send marshaled IP_USERS to other clients AND discovery to notify them of the dead
    ip_users_marsh, err := json.Marshal(IP_USERS)
    if err != nil {
        fmt.Println("Error marshalling IP_USERS!")
        return
    }

    // 1.) First tell discovery server new list for this conversation
    header_vals := make(map[string]string)
    header_vals["vectorclock"] = currentVectorClockTimeString()
    _, success := util.PutReq(
        "http://" + PARAMETERS["server_addr"] + "/channels/" + PARAMETERS["channel"] + "/new_ip_slice",
        string(ip_users_marsh),
        header_vals)
    if !success {
        fmt.Println("Error in mark_as_dead with PUT to new_ip_slice")
    }

    // 2.) Now tell all other live members in the channel
    for ip, _ := range IP_USERS {
        broadcast_entry_to_conv(ip, ip_users_marsh)
    }

    return
}

func currentVectorClockTimeString() string {
    res,_ := json.Marshal(VECTOR_CLOCK)
    return string(res)
}

func updateVectorClockBasedOnString(seen_stamp string){
    var other_vc VectorClock;
    err := json.Unmarshal([]byte(seen_stamp), &other_vc)
    if err != nil{
        fmt.Println(err)
        return
    }
    updateVectorClockBasedOn(other_vc)
}

func updateVectorClockBasedOn(seen_stamp VectorClock){
    // Update VECTOR CLOCK.  Might be missing entries!
    CLOCK_LOCK.Lock()
    for ip, time := range seen_stamp{
        if _, ok := VECTOR_CLOCK[ip]; !ok{
            // Oops!  We don't have an entry for this IP yet!
            VECTOR_CLOCK[ip] = 0
        }
        // Jump to presented time if it's later.
        if time > VECTOR_CLOCK[ip]{
            VECTOR_CLOCK[ip] = time
        }
    }
    CLOCK_LOCK.Unlock()
    // You probably just got incremented.
    updateMyVectorClockEntry() // for +1 of own clock

}

func updateMyVectorClockEntry(){
    CLOCK_LOCK.Lock()
    VECTOR_CLOCK[PARAMETERS["client_ip"] + ":" + PARAMETERS["client_port"]]++
    CLOCK_LOCK.Unlock()
}
