package config

type Config struct {
	Source      string `yaml:"source"`
	BuildScript string `yaml:"build-script"`
	OutputFile  string `yaml:"output-file"`
	VendorCert  string `yaml:"vendor-cert"`
	Sbat        string `yaml:"sbat"`
}
