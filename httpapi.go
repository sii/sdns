// sdns web api.
// This is used to receive commands from sdnsweb.

package main

import (
	"fmt"
	"strconv"
	"net/http"
	"github.com/gorilla/mux"
)

func HTTPRootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Nothing here.")
}

func HTTPSetHostHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	if vars["key"] != config.httpApiKey {
		fmt.Fprintf(w, "error: no")
		return
	}
	if queryLog {
		fmt.Println("Set host called:", vars["hostname"], vars["dstIP"])
	}
	err := DefaultDomainHandler.setHost(vars["hostname"], vars["dstIP"])
	if err == nil {
		fmt.Fprintf(w, "ok")
	} else {
		fmt.Fprintf(w, "error: %v", err)
	}
}

func startHTTPListener(port int) {
	fmt.Printf("Starting HTTP listener on %d\n", port)
	r := mux.NewRouter()
	r.HandleFunc("/", HTTPRootHandler)
	r.HandleFunc("/set/host/{key}/{hostname}/{dstIP}/", HTTPSetHostHandler)
	http.Handle("/", r)
	http.ListenAndServe(":" + strconv.Itoa(port), nil)
}

