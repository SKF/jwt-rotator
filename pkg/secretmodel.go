package pkg

import "github.com/SKF/go-rest-utility/client/auth"

type StoredToken struct {
	RawToken auth.RawToken `json:"token"`
}
