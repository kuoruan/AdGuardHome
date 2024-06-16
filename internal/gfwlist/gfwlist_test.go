package gfwlist

import (
	"testing"
)

func TestFetchGFWList(t *testing.T) {

}

func TestNewGFWList(t *testing.T) {

}

func TestParseGFWList(t *testing.T) {
	data, err := fetchGFWList()

	if err != nil {
		t.Errorf("fetch gfwlist failed: %v", err)
		return
	}

	_, err = ParseGFWList(data)

	if err != nil {
		t.Errorf("parse gfwlist failed: %v", err)
		return
	}
}
