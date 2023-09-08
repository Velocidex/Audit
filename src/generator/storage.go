package generator

import (
	"io/ioutil"
	"os"
	"strings"

	"encoding/json"

	"github.com/Velocidex/yaml/v2"
)

func (self *Rules) Save(filename string) error {
	out_fd, err := os.OpenFile(filename,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out_fd.Close()

	if strings.HasSuffix(filename, "json") {
		encoder := json.NewEncoder(out_fd)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", " ")

		return encoder.Encode(self)
	}

	// Otherwise encode in yaml
	serialized, err := yaml.Marshal(self)
	if err != nil {
		return err
	}

	_, err = out_fd.Write(serialized)
	return err
}

func LoadModel(filename string) (*Rules, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}

	res := &Rules{}
	err = yaml.Unmarshal(data, res)
	return res, err
}
