package main

import (
	"crypto/md5"
	"fmt"
	"io"
	//"log"
	//	"log"
	"os"
	"strings"
	"sync"

	_ "github.com/go-sql-driver/mysql"

	"github.com/jmoiron/sqlx"
	"github.com/tidwall/redcon"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"gopkg.in/natefinch/lumberjack.v2"
)

var addr = ":6379"

var mu sync.RWMutex
var db *sqlx.DB
var items map[string][]byte
var l *zap.SugaredLogger

// 1589167111.520663 [0 127.0.0.1:38636] "publish" "turn/realm/xrealm/user/user/allocation/002000000000000005/traffic" "rcvp=956, rcvb=99400, sentp=1092, sentb=113504"
// 1589167111.520809 [0 127.0.0.1:38638] "publish" "turn/realm/xrealm/user/user/allocation/001000000000000004/traffic" "rcvp=1092, rcvb=113552, sentp=956, sentb=99360"
// 1589167133.544963 [0 127.0.0.1:38638] "publish" "turn/realm/xrealm/user/user/allocation/001000000000000004/traffic" "rcvp=919, rcvb=95576, sentp=1055, sentb=109656"
// 1589167133.545034 [0 127.0.0.1:38638] "publish" "turn/realm/xrealm/user/user/allocation/001000000000000004/total_traffic" "rcvp=2011, rcvb=209128, sentp=2011, sentb=209016"
// 1589167133.556956 [0 127.0.0.1:38636] "publish" "turn/realm/xrealm/user/user/allocation/002000000000000005/traffic" "rcvp=1055, rcvb=109720, sentp=919, sentb=95512"
// 1589167133.557029 [0 127.0.0.1:38636] "publish" "turn/realm/xrealm/user/user/allocation/002000000000000005/total_traffic" "rcvp=2011, rcvb=209120, sentp=2011, sentb=209016"
// 1589167765.113439 [0 127.0.0.1:38638] "publish" "turn/realm/xrealm/user/user/allocation/001000000000000003/traffic" "rcvp=3, rcvb=276, sentp=3, sentb=320"
// 1589167765.113499 [0 127.0.0.1:38638] "publish" "turn/realm/xrealm/user/user/allocation/001000000000000003/total_traffic" "rcvp=3, rcvb=276, sentp=3, sentb=320"
// 1589167863.806918 [0 127.0.0.1:38640] "publish" "turn/realm/xrealm/user/user/allocation/000000000000000004/traffic" "rcvp=3, rcvb=284, sentp=3, sentb=320"
// 1589167863.806980 [0 127.0.0.1:38640] "publish" "turn/realm/xrealm/user/user/allocation/000000000000000004/total_traffic" "rcvp=3, rcvb=284, sentp=3, sentb=320"

// "publish" "turn/realm/xrealm/user/user/allocation/000000000000000004/traffic" "rcvp=3, rcvb=284, sentp=3, sentb=320"
// "publish" "turn/realm/xrealm/user/user/allocation/000000000000000004/total_traffic

func handleTrafficReport(report string, totalTraffic bool, ispeer bool, session uint64) {

	var rcvp, rcvb, sentp, sentb uint64
	n, err := fmt.Sscanf(report, "rcvp=%d, rcvb=%d, sentp=%d, sentb=%d", &rcvp, &rcvb, &sentp, &sentb)
	if err != nil || n != 4 {
		l.Error("scanf failed", report, n, err)
		return
	}

	l.Info("traffic nums", rcvp, rcvb, sentp, sentb)

	traffic := `INSERT INTO traffic (total_traffic,ispeer,sessionid,rcvp,rcvb,sentp,sentb) VALUES (?,?,?,?,?,?,?)`
	db.MustExec(traffic, totalTraffic, ispeer, session, rcvp, rcvb, sentp, sentb)
}

// needs to be reentrant capable
func publish(conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
		return
	}

	var realm string
	var user string
	var session uint64

	var replacer = strings.NewReplacer("/", " ")

	path := replacer.Replace(string(cmd.Args[1]))

	// XXX dont need peer traffic for now
	// if !strings.HasSuffix(path, "traffic/peer") {
	// 	return
	// }
	// 	l.Infof("### got peer")

	if !strings.HasSuffix(path, "traffic") {
		return
	}

	matchpath := replacer.Replace("turn/realm/%s/user/%s/allocation/%d/total_traffic")
	n, err := fmt.Sscanf(path, matchpath, &realm, &user, &session)
	if err == nil && n == 3 {
		l.Infof("total_traffic  %v", []interface{}{realm, user, session, string(cmd.Args[2])})

		handleTrafficReport(string(cmd.Args[2]), true, false, session)
	}

	matchpath = replacer.Replace("turn/realm/%s/user/%s/allocation/%d/traffic")
	n, err = fmt.Sscanf(path, matchpath, &realm, &user, &session)
	if err == nil && n == 3 {
		l.Infof("traffic %v", []interface{}{realm, user, session, string(cmd.Args[2])})

		handleTrafficReport(string(cmd.Args[2]), false, false, session)
	}

}

// needs to be reentrant capable
func keys(conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
		return
	}

	conn.WriteArray(0)

	switch string(cmd.Args[1]) {
	case "condition":
	default:
	}

	// count:=4
	// conn.WriteArray(count)
	// for i := 0; i < count; i++ {

	// }
}

func hmackey(username string, realm string, pass string) string {
	h := md5.New()
	//io.WriteString(h, "myusername:my.realm.org:my-password")
	//0xe10f73302e450157172ca2b8dfb3b157
	io.WriteString(h, username)
	io.WriteString(h, ":")
	io.WriteString(h, realm)
	io.WriteString(h, ":")
	io.WriteString(h, pass)

	return fmt.Sprintf("%x", h.Sum(nil))
}

func get(conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
		return
	}
	ok := false

	// "get" "turn/realm/xrealm/user/user/key"

	k := string(cmd.Args[1])
	// var realm string
	// var user string
	// n, err := fmt.Sscanf(k, "turn/realm/%s/user/%s/key", &realm, &user)
	// if err != nil {
	// 	panic(err)
	// }
	// if n==2 {
	// 	go log.Printf("lt user creds request: %s %s",realm,user)
	// }

	ok = k == "turn/realm/xrealm/user/user/key"
	val := []byte(hmackey("user", "xrealm", "pass"))

	l.Infof("matching user yes/no %t", ok)

	//old
	// mu.RLock()
	// val, ok := items[string(cmd.Args[1])]
	// mu.RUnlock()
	if !ok {
		conn.WriteNull()
	} else {
		conn.WriteBulk(val)
	}

}

func logInit(f io.WriteCloser) *zap.SugaredLogger {

	pe := zap.NewProductionEncoderConfig()

	fileEncoder := zapcore.NewJSONEncoder(pe)

	foo := zapcore.EncoderConfig{
		TimeKey:        "",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.RFC3339TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	//foo=zap.NewDevelopmentEncoderConfig()
	consoleEncoder := zapcore.NewConsoleEncoder(foo)
	//pe.EncodeTime = zapcore.RFC3339TimeEncoder

	// level := zap.InfoLevel
	// if d {
	//     level = zap.DebugLevel
	// }

	core := zapcore.NewTee(
		zapcore.NewCore(fileEncoder, zapcore.AddSync(f), zapcore.DebugLevel),
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), zap.DebugLevel),
	)

	ll := zap.New(core) // Creating the logger

	return ll.Sugar()
}

func logInitx(f io.WriteCloser) *zap.SugaredLogger {

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(f),
		zap.InfoLevel,
	)

	return zap.New(core).Sugar()
}

func main() {
	// lumberjack.Logger is already safe for concurrent use, so we don't need to
	// lock it.
	lj := &lumberjack.Logger{
		Filename:   "/var/log/freeturn/coturn-stats-monitor.log",
		MaxSize:    100, // megabytes
		MaxBackups: 100, // maximum number of files
		MaxAge:     365, // days
	}

	l = logInit(lj)

	go l.Infof("foofoo3")

	items = make(map[string][]byte)

	//open and ping
	db = sqlx.MustConnect("mysql", "mysqluser:yuLtrUb74EMYzp7@tcp(localhost:3306)/novadb")
	go l.Infof("mysql open okay")

	go l.Infof("started server at %s", addr)
	err := redcon.ListenAndServe(addr,
		func(conn redcon.Conn, cmd redcon.Command) {

			//cmd0 := strings.ToLower(string(cmd.Args[0]))
			//l.Printf("command received %s:  %s", cmd0)

			var sb strings.Builder

			for i, v := range cmd.Args {
				sb.WriteString(string(v))
				if i < len(cmd.Args)-1 {
					sb.WriteRune(' ')
				}
			}

			str := sb.String()

			if str == "publish __XXX__ __YYY__" {
				return
			}

			// log the command
			l.Debug(str)

			switch strings.ToLower(string(cmd.Args[0])) {
			default:
				conn.WriteError("ERR unknown command '" + string(cmd.Args[0]) + "'")
			case "detach":
				hconn := conn.Detach()
				l.Infof("connection has been detached")
				go func() {
					defer hconn.Close()
					hconn.WriteString("OK")
					hconn.Flush()
				}()
				return

			case "publish":
				publish(conn, cmd)
			case "keys":
				keys(conn, cmd)
			case "ping":
				conn.WriteString("PONG")
			case "quit":
				conn.WriteString("OK")
				conn.Close()
			case "set":
				if len(cmd.Args) != 3 {
					conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
					return
				}
				mu.Lock()
				items[string(cmd.Args[1])] = cmd.Args[2]
				mu.Unlock()
				conn.WriteString("OK")
			case "get":
				get(conn, cmd)

			case "del":
				if len(cmd.Args) != 2 {
					conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
					return
				}
				mu.Lock()
				_, ok := items[string(cmd.Args[1])]
				delete(items, string(cmd.Args[1]))
				mu.Unlock()
				if !ok {
					conn.WriteInt(0)
				} else {
					conn.WriteInt(1)
				}
			}
		},
		func(conn redcon.Conn) bool {
			// use this function to accept or deny the connection.
			l.Infof("accept: %s", conn.RemoteAddr())

			return true
		},
		func(conn redcon.Conn, err error) {
			// this is called when the connection has been closed
			// l.Printf("closed: %s, err: %v", conn.RemoteAddr(), err)
		},
	)
	if err != nil {
		l.Fatal(err)
	}
}
