package main

import (
    "fmt"
    "github.com/gin-gonic/gin"
    "strings"
    "os"
    // "net/http"
    "encoding/json"
    "go-wechat-hw1-team04/util"
)

// client struct contains IP and Username
type clientData struct {
    ip string
    username string
}

var SESSIONS map[string]map[string]string // channel:(ip:user)
var SESSION_PWS map[string]string
var SEQ_NUM int

var CALL_INSTRUCTION string = "./discovery [serverPort]"
var ARGUMENT_COUNT = 2;

func main() {
    // TODO remove after implementing lamport clocks
    SEQ_NUM = 24

    // Get discovery server port
    args := os.Args
    if len(args) != ARGUMENT_COUNT {
        fmt.Println("Wrong parameter count!");
        fmt.Println(CALL_INSTRUCTION);
        return
    }
    server_port := args[1]
    server_ip, err := util.MyIP()
    if err != nil {
        fmt.Println("I can't figure out my IP address!  Shutting down... :(")
        return
    }
    fmt.Println("We're running on " + server_ip + ":" + server_port)

    // For storing IP addresses of each conversation
    SESSIONS = make(map[string]map[string]string)
    SESSION_PWS = make(map[string]string)

    // Setup server object
    r := gin.Default()

    // Define all server protocols
    r.PUT("/channels/:channel/create/:username", create_channel) // when client requests to join a channel
    r.PUT("/channels/:channel/join/:username", join_channel) // when client requests to join a channel
    r.PUT("/channels/:channel/new_ip_slice", recieve_new_ip_slice) // when client detects dead
    r.GET("/", get_server_version) // gives back csv of server versions
    r.GET("/channels/:channel/directory", get_directory) // give back user list of a specified channel

    // Run server on port 8080
    r.Run(":" + server_port)
}

func create_channel(c *gin.Context) {
    /*
    After recieving, do the following protocol

    1.) Check if channel name is already taken
    1.F) If False:
        Throw 401 CONFLICT (channel already exists)
    1.T) If True:
        Create channel with the given password and return 200 OK + include
            session: <channel>
            sequence: <lamport number>
            version: <1.0>
    */

    // gets client IP,pw from raw string being passed
    join_info, _ := c.GetRawData()
    s := strings.Split(string(join_info), ",")
    client_ip, channel_pw := s[0], s[1]

    // params contain the username and channel of sender
    username := c.Param("username")
    channel := c.Param("channel")

    // 1.) Check if channel name is taken
    if _, ok := SESSIONS[channel]; ok{ // if channel exist throw 401
        c.JSON(401, gin.H{"message":"401 -> CONFLICT (channel already exists)",})
        return
    }

    // 1.T) Let them join the channel if they pass all error checks
    ip_map := make(map[string]string) // init map of ip:username
    ip_map[client_ip] = username // insert username for creating ip
    SESSIONS[channel] = ip_map // for this channel, insert the map
    SESSION_PWS[channel] = channel_pw // for this channel, insert password

    // create list of ips and all users to send back and send it back
    all_ips := make([]string, 0);
    all_users := make([]string, 0);
    for ip, user := range SESSIONS[channel]{
        all_ips = append(all_ips, ip)
        all_users = append(all_users, user)
    }
    all_ips_string := strings.Join(all_ips, ",")
    all_users_string := strings.Join(all_users, ",")
    c.JSON(200, gin.H{"message":"200 -> OK", "session":channel, "sequence":SEQ_NUM, "version":54, "all_ips_string":all_ips_string, "all_users_string":all_users_string})

    return
}

func join_channel(c *gin.Context) {
    /*
    After recieving, do following protocol:

    1.) Check if channel exists:
    1.F) If False:
        Throw 404 NOT FOUND (channel does not exist)
    1.T) If True:
        2.) Check if pw is correct,
        2.F) If False:
            Throw 401 UNAUTHORIZED (channel password is incorrect)
        2.T) If True:
            3.) Check if username is taken in the channel or not
            3.F) If False:
                Throw 409 CONFLICT (username already in channel)
            3.T) If True:
                Let them join the channel list of IP's and return 200 OK + include
                    session: <channel>
                    sequence: <lamport number>
                    version: <1.0>
    */

    // gets client IP,pw from raw string being passed
    join_info, _ := c.GetRawData()
    s := strings.Split(string(join_info), ",")
    client_ip, channel_pw := s[0], s[1]

    // params contain the username and channel of sender
    username := c.Param("username")
    channel := c.Param("channel")

    // START ERROR CHECK 1.) Check if channel exists
    if _, ok := SESSIONS[channel]; !ok{ // if channel doesn't exist throw 404
        c.JSON(404, gin.H{"message":"404 -> NOT FOUND (channel does not exist)",})
        return
    }

    // 2.) Check if pw is correct
    if strings.Compare(channel_pw, SESSION_PWS[channel]) != 0{ // if pw not correct
        c.JSON(401, gin.H{"message":"401 -> UNAUTHORIZED (channel password is incorrect)"})
        return
    }

    // END ERROR CHECK 3.) Check if username is taken in the channel or not
    for _, user := range SESSIONS[channel]{
        if strings.Compare(user, username) == 0 { // if username exists in this channel
            // can't have dup usernames
            c.JSON(409, gin.H{"message": "409 -> CONFLICT (username already in channel)"})
            return
        }
    }

    // 3.T) Let them join the channel if they pass all error checks
    SESSIONS[channel][client_ip] = username // for this channel, insert the map

    // create list of ips and all users to send back and send it back
    all_ips := make([]string, 0);
    all_users := make([]string, 0);
    for ip, user := range SESSIONS[channel]{
        all_ips = append(all_ips, ip)
        all_users = append(all_users, user)
    }
    all_ips_string := strings.Join(all_ips, ",")
    all_users_string := strings.Join(all_users, ",")
    c.JSON(200, gin.H{"message":"200 -> OK", "session":channel, "sequence":SEQ_NUM, "version":54, "all_ips_string":all_ips_string, "all_users_string":all_users_string})

    return
}

func recieve_new_ip_slice(c *gin.Context) {
    // Get the raw IP_USERS from sender
    ip_users_string, err := c.GetRawData()
    channel := c.Param("channel")
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
    // If successful, replace local IP_USERS in SESSIONS in corresponding channel
    SESSIONS[channel] = incoming_ip_users

    return
}

func get_server_version(c *gin.Context) {
    c.JSON(200, gin.H{"message":"200 -> OK", "version":"1.999"})
}

func get_directory(c *gin.Context){
    channel_pw := c.GetHeader("session")
    channel := c.Param("channel")
    if strings.Compare(channel_pw, SESSION_PWS[channel]) == 0 { // if password correct, create user list and respond
        users_slice := make([]string, 0)
        for _, user := range SESSIONS[channel] {
            users_slice = append(users_slice, user)
        }
        users_csv := strings.Join(users_slice, ",")
        c.JSON(200, gin.H{"message":"200 -> OK", "request body":users_csv})
    } else {
        c.JSON(401, gin.H{"message":"401 -> UNAUTHORIZED"})
    }

}
