package generator

import (
	"io/ioutil"
	"os"

	"encoding/json"
)

func (self *Rules) Save(filename string) error {
	out_fd, err := os.OpenFile(filename,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out_fd.Close()

	encoder := json.NewEncoder(out_fd)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", " ")

	return encoder.Encode(self)
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
	err = json.Unmarshal(data, res)
	return res, err
}
