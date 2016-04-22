// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	elastigo "github.com/mattbaird/elastigo/lib"
	"os"
	"strings"
	"time"
)

const docsPerSearch int = 100

type config struct {
	eshost    string
	startDate time.Time
	endDate   time.Time
	hostmatch string

	results []event
}

var cfg config

type queryCriteria struct {
	QueryString map[string]string            `json:"query_string,omitempty"`
	Term        map[string]string            `json:"term,omitempty"`
	Match       map[string]string            `json:"match,omitempty"`
	Range       map[string]map[string]string `json:"range,omitempty"`
}

type queryContainer struct {
	From  int               `json:"from"`
	Size  int               `json:"size"`
	Sort  map[string]string `json:"sort"`
	Query struct {
		Bool struct {
			Must           []queryCriteria `json:"must,omitempty"`
			Should         []queryCriteria `json:"should,omitempty"`
			MinShouldMatch int             `json:"minimum_should_match"`
		} `json:"bool"`
	} `json:"query"`
}

func (q *queryContainer) defaultSettings() error {
	q.From = 0
	q.Size = docsPerSearch
	q.Sort = make(map[string]string)
	q.Sort["utctimestamp"] = "asc"

	q.Query.Bool.MinShouldMatch = 1

	var qc queryCriteria
	qc.Range = make(map[string]map[string]string)
	qc.Range["utctimestamp"] = make(map[string]string)
	qc.Range["utctimestamp"]["gte"] = cfg.startDate.Format(time.RFC3339)
	qc.Range["utctimestamp"]["lte"] = cfg.endDate.Format(time.RFC3339)
	q.Query.Bool.Must = append(q.Query.Bool.Must, qc)

	if cfg.hostmatch != "" {
		qc = queryCriteria{}
		qc.QueryString = make(map[string]string)
		qc.QueryString["query"] = fmt.Sprintf("hostname: /%v/", cfg.hostmatch)
		q.Query.Bool.Should = append(q.Query.Bool.Should, qc)

		qc = queryCriteria{}
		qc.QueryString = make(map[string]string)
		qc.QueryString["query"] = fmt.Sprintf("details.dhost: /%v/", cfg.hostmatch)
		q.Query.Bool.Should = append(q.Query.Bool.Should, qc)

		qc = queryCriteria{}
		qc.QueryString = make(map[string]string)
		qc.QueryString["query"] = fmt.Sprintf("details.hostname: /%v/", cfg.hostmatch)
		q.Query.Bool.Should = append(q.Query.Bool.Should, qc)
	}
	return nil
}

func (q *queryContainer) addMatch(key string, val string) {
	var qc queryCriteria
	qc.Match = make(map[string]string)
	qc.Match[key] = val
	q.Query.Bool.Must = append(q.Query.Bool.Must, qc)
}

type event struct {
	Category     string    `json:"category"`
	Hostname     string    `json:"hostname"`
	Timestamp    time.Time `json:"timestamp"`
	UTCTimestamp time.Time `json:"utctimestamp"`
	Summary      string    `json:"summary"`
	Details      struct {
		Hostname     string `json:"hostname"`
		Command      string `json:"command"`
		DHost        string `json:"dhost"`
		DProc        string `json:"dproc"`
		DUser        string `json:"duser"`
		SUser        string `json:"suser"`
		Fname        string `json:"fname"`
		Name         string `json:"name"`
		ProcessName  string `json:"processname"`
		OriginalUser string `json:"originaluser"`
		User         string `json:"user"`
		Path         string `json:"path"`
	} `json:"details"`
}

func (e *event) normalize() error {
	if e.Hostname == "" && e.Details.DHost != "" {
		e.Hostname = e.Details.DHost
	}
	if e.Details.User == "" && e.Details.DUser != "" {
		e.Details.User = e.Details.DUser
	}
	if e.Details.Path == "" && e.Details.Fname != "" {
		e.Details.Path = e.Details.Fname
	}
	if e.Details.OriginalUser == "" && e.Details.SUser != "" {
		e.Details.OriginalUser = e.Details.SUser
	}
	if e.Details.ProcessName == "" && e.Details.DProc != "" {
		e.Details.ProcessName = e.Details.DProc
	}
	if e.Details.Name == "Unix Exec" {
		e.Category = "execve"
	}

	e.Summary = strings.Trim(e.Summary, " \n")
	return nil
}

func getESHost() error {
	cfg.eshost = os.Getenv("MOZDEFESHOST")
	if cfg.eshost == "" {
		return errors.New("MOZDEFESHOST environment variable not set")
	}
	return nil
}

func parseDates(begin string, end string) error {
	var err error
	cfg.startDate, err = time.Parse("2006-01-02 15:04:05", begin)
	if err != nil {
		return err
	}
	if end == "" {
		cfg.endDate = time.Now().UTC()
	} else {
		cfg.endDate, err = time.Parse("2006-01-02 15:04:05", end)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	err := getESHost()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	auditmode := flag.Bool("a", false, "search for audit events")
	syslogmode := flag.Bool("s", false, "search for syslog events")
	begindate := flag.String("b", "", "start date for search in UTC (yyyy-mm-dd hh:mm:ss)")
	enddate := flag.String("e", "", "end date for search in UTC (yyyy-mm-dd hh:mm:ss, defaults to now)")
	noop := flag.Bool("n", false, "dont search, just prints first query in json and exits")
	hostmatch := flag.String("H", "", "match events for hostname matching regexp")
	flag.Parse()

	if !*auditmode && !*syslogmode {
		fmt.Fprintf(os.Stderr, "error: must specify -a or -s\n")
		os.Exit(1)
	}

	err = parseDates(*begindate, *enddate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	cfg.hostmatch = *hostmatch

	var qry queryContainer
	if *auditmode {
		qry, err = buildAuditSearch()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if *noop {
			buf, err := json.MarshalIndent(qry, "", "    ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stdout, "%v\n", string(buf))
			os.Exit(0)
		}
		err = runQuery(qry, "auditd")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		auditResults()
	} else if *syslogmode {
		qry, err = buildSyslogSearch()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if *noop {
			buf, err := json.MarshalIndent(qry, "", "    ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stdout, "%v\n", string(buf))
			os.Exit(0)
		}
		err = runQuery(qry, "event")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		syslogResults()
	}
}

func auditResults() {
	for _, x := range cfg.results {
		evstr := "unknown audit event"
		if x.Category == "execve" {
			evstr = "[execve]"
			origuser := "none"
			if x.Details.OriginalUser != "" {
				origuser = x.Details.OriginalUser
			}
			evstr += fmt.Sprintf(" (%v/%v)", origuser, x.Details.User)
			if x.Details.Command != "" {
				evstr += fmt.Sprintf(" command:%q", x.Details.Command)
			}
			if x.Details.DProc != "" {
				evstr += fmt.Sprintf(" proc:%q", x.Details.ProcessName)
			}
			if x.Details.Path != "" {
				evstr += fmt.Sprintf(" path:%q", x.Details.Path)
			}
		}
		fmt.Fprintf(os.Stdout, "%v %v %v\n", x.Timestamp,
			x.Hostname, evstr)
	}
}

func syslogResults() {
	for _, x := range cfg.results {
		evstr := "[syslog] unknown syslog event"
		if x.Summary != "" {
			evstr = fmt.Sprintf("[syslog] %v", x.Summary)
		}
		fmt.Fprintf(os.Stdout, "%v %v %v\n", x.Timestamp,
			x.Details.Hostname, evstr)
	}
}

func runQuery(qry queryContainer, doctype string) error {
	indices := make([]string, 0)
	dp := cfg.startDate
	for {
		idx := fmt.Sprintf("events-%v", dp.Format("20060102"))
		indices = append(indices, idx)
		if cfg.endDate.Sub(dp) < time.Duration(time.Hour*24) {
			idx = fmt.Sprintf("events-%v", cfg.endDate.Format("20060102"))
			found := false
			for _, x := range indices {
				if x == idx {
					found = true
					break
				}
			}
			if !found {
				indices = append(indices, idx)
			}
			break
		}
		dp = dp.Add(time.Hour * 24)
	}
	for _, x := range indices {
		err := runQueryIndex(qry, x, doctype)
		if err != nil {
			return err
		}
	}
	return nil
}

func runQueryIndex(qry queryContainer, index string, doctype string) error {
	conn := elastigo.NewConn()
	defer conn.Close()
	conn.Domain = cfg.eshost
	qry.From = 0
	for i := 0; ; i += docsPerSearch {
		res, err := conn.Search(index, doctype, nil, qry)
		if err != nil {
			return err
		}
		if res.Hits.Len() == 0 {
			break
		}
		for _, x := range res.Hits.Hits {
			var nev event
			err = json.Unmarshal(*x.Source, &nev)
			if err != nil {
				return err
			}
			err = nev.normalize()
			if err != nil {
				return err
			}
			cfg.results = append(cfg.results, nev)
			//fmt.Println(string(*x.Source))
		}
		qry.From += docsPerSearch
	}
	return nil
}

func buildAuditSearch() (queryContainer, error) {
	var ret queryContainer
	err := ret.defaultSettings()
	if err != nil {
		return ret, err
	}
	ret.addMatch("_type", "auditd")
	return ret, nil
}

func buildSyslogSearch() (queryContainer, error) {
	var ret queryContainer
	err := ret.defaultSettings()
	if err != nil {
		return ret, err
	}
	ret.addMatch("_type", "event")
	ret.addMatch("category", "syslog")
	return ret, nil
}
