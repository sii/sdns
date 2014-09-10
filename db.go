// sdns database functions.
// sdns only uses the database on startup to load existing records.
// No db queries are made during normal operation.

/*
grant all on sdns.* to 'sdns'@'%' identified by 'my-password';

create database sdns;
use sdns;

create table host_records (
	id INT NOT NULL AUTO_INCREMENT,
	hostname VARCHAR(100),
	dst_ip VARCHAR(50),
	submit_ip varchar(50),
	updated INT,
	created INT,
	PRIMARY KEY(id),
	CONSTRAINT host_c UNIQUE (hostname)
);
create index hostname_idx on host_records (hostname);

create table host_registry (
	hostname VARCHAR(100),
	access_key VARCHAR(50),
	submit_ip varchar(50),
	locked TINYINT,
	created INT,
	PRIMARY KEY(hostname)
);
*/

package main

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"strconv"
)

func loadRecords(dh *DomainHandler, hostname, username, password, dbname string) (uint32, error) {
	var cnt uint32 = 0
	dsn := username + ":" + password + "@tcp(" + hostname + ":" + strconv.Itoa(sqlPort) + ")/" + dbname
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return cnt, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT hostname, dst_ip FROM host_records")
	if err != nil {
		return cnt, err
	}
	for rows.Next() {
		var hostname, dstIP string
		cnt += 1
		if err := rows.Scan(&hostname, &dstIP); err != nil {
			return cnt, err
		}
		err := dh.setHost(hostname, dstIP)
		if err != nil {
			return cnt, err
		}
	}
	return cnt, nil
}
