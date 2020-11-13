package config

import (
	"encoding/json"
	"fmt"
	"github.com/racirx/mob/authentication"
	"github.com/racirx/mob/authentication/auth0"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
)

type Config struct {
	ServerConfig  Server        `json:"server"`
	Authenticator Authenticator `json:"authenticator"`
}

type Logger struct {
	Level    zapcore.Level
	Encoding string
}

func (l *Logger) UnmarshalJSON(b []byte) error {
	var conf struct {
		Level    string `json:"level"`
		Encoding string `json:"encoding"`
	}

	if err := json.Unmarshal(b, &conf); err != nil {
		return err
	}

	var level zapcore.Level
	switch conf.Level {
	case "debug":
		level = zap.DebugLevel
	case "info":
		level = zap.InfoLevel
	case "warn":
		level = zap.WarnLevel
	case "panic":
		level = zap.PanicLevel
	case "fatal":
		level = zap.FatalLevel
	default:
		return fmt.Errorf("not matching log level found for %s", conf.Level)
	}

	*l = Logger{
		Level:    level,
		Encoding: conf.Encoding,
	}

	return nil
}

type Server struct {
	Port   string
	Key    string
	Logger Logger
}

type Authenticator struct {
	Type   string               `json:"type"`
	Config AuthenticationConfig `json:"config"`
}

func (a *Authenticator) UnmarshalJSON(b []byte) error {
	var auth struct {
		Type   string          `json:"type"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(b, &auth); err != nil {
		return fmt.Errorf("parse authenticator: %v", err)
	}
	f, ok := AuthenticatorsConfig[auth.Type]
	if !ok {
		return fmt.Errorf("unknown connector type %q", auth.Type)
	}

	connConfig := f()
	if len(auth.Config) != 0 {
		data := []byte(os.ExpandEnv(string(auth.Config)))
		if err := json.Unmarshal(data, connConfig); err != nil {
			return fmt.Errorf("parse connector config: %v", err)
		}
	}

	*a = Authenticator{
		Type:   auth.Type,
		Config: connConfig,
	}

	return nil
}

type AuthenticationConfig interface {
	Open(logger *zap.Logger) (authentication.Provider, error)
}

var AuthenticatorsConfig = map[string]func() AuthenticationConfig{
	"auth0": func() AuthenticationConfig { return new(auth0.Config) },
}
