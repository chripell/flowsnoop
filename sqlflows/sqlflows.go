package sqlflows

import (
	"database/sql"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/chripell/flowsnoop/flow"
	_ "github.com/mattn/go-sqlite3"
)

type SqlFlows struct {
	db       *sql.DB
	prevTick time.Time
}

var (
	sqlDB = flag.String("sqlflows_db", "/tmp/DELME.db",
		"Database file name.")
)

// julian calculates the Julian date, provided it's within 209 years
// of Jan 2, 2006.
func julian(t time.Time) float64 {
	// Julian date, in seconds, of the "Format" standard time.
	// (See http://www.onlineconversion.com/julian_date.htm)
	const julian = 2453738.4195
	// Easiest way to get the time.Time of the Unix time.
	// (See comments for the UnixDate in package Time.)
	unix := time.Unix(1136239445, 0)
	const oneDay = float64(86400. * time.Second)
	return julian + float64(t.Sub(unix))/oneDay
}

func pip(ip []byte) string {
	return net.IP(ip).String()
}

func (sf *SqlFlows) Init() (err error) {
	sf.db, err = sql.Open("sqlite3", *sqlDB)
	if err != nil {
		return fmt.Errorf("cannot open db %s: %w", *sqlDB, err)
	}
	if err = sf.db.Ping(); err != nil {
		return fmt.Errorf("error pinging db %s: %w", *sqlDB, err)
	}
	_, err = sf.db.Exec(`
CREATE TABLE IF NOT EXISTS flows (
jd FLOAT,
proto INTEGER,
src_ip TEXT,
src_port INTEGER,
dst_ip TEXT,
dst_port INTEGER,
bytes_sec FLOAT);
`)
	if err != nil {
		return fmt.Errorf("create or insert failed: %w", err)
	}
	return nil
}

func (sf *SqlFlows) Push(tick time.Time,
	flowsL4 flow.List4, flowsM4 flow.Map4,
	flowsL6 flow.List6, flowsM6 flow.Map6) error {
	if sf.prevTick.IsZero() {
		sf.prevTick = tick
		return nil
	}
	delta := float64(tick.Sub(sf.prevTick)) / 1_000_000_000.0
	sf.prevTick = tick
	jd := julian(tick)
	tx, err := sf.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction failed: %w", err)
	}
	stmt, err := tx.Prepare("insert into flows(jd, src_ip, src_port, dst_ip, dst_port, proto, bytes_sec) values(?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("prepare failed: %w", err)
	}
	defer stmt.Close()
	for _, fl := range flowsL4 {
		_, err = stmt.Exec(jd, pip(fl.Flow.SrcIP[:]), fl.Flow.SrcPort,
			pip(fl.Flow.DstIP[:]), fl.Flow.DstPort, fl.Flow.Proto, float64(fl.Tot)/delta)
		if err != nil {
			return fmt.Errorf("exec failed: %w", err)
		}
	}
	for fl, tot := range flowsM4 {
		_, err = stmt.Exec(jd, pip(fl.SrcIP[:]), fl.SrcPort,
			pip(fl.DstIP[:]), fl.DstPort, fl.Proto, float64(tot)/delta)
		if err != nil {
			return fmt.Errorf("exec failed: %w", err)
		}
	}
	for _, fl := range flowsL6 {
		_, err = stmt.Exec(jd, pip(fl.Flow.SrcIP[:]), fl.Flow.SrcPort,
			pip(fl.Flow.DstIP[:]), fl.Flow.DstPort, uint16(fl.Flow.Proto)+256, float64(fl.Tot)/delta)
		if err != nil {
			return fmt.Errorf("exec failed: %w", err)
		}
	}
	for fl, tot := range flowsM6 {
		_, err = stmt.Exec(jd, pip(fl.SrcIP[:]), fl.SrcPort,
			pip(fl.DstIP[:]), fl.DstPort, uint16(fl.Proto)+256, float64(tot)/delta)
		if err != nil {
			return fmt.Errorf("exec failed: %w", err)
		}
	}
	tx.Commit()
	return nil
}

func (sf *SqlFlows) Finalize() error {
	sf.db.Close()
	return nil
}

func New() *SqlFlows {
	return &SqlFlows{}
}
