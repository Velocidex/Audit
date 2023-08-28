package generator

import (
	"io/ioutil"
	"os"

	"www.velocidex.com/golang/velociraptor/json"
)

func (self *Rules) Save(filename string) error {
	serialized := json.MustMarshalIndent(self)
	out_fd, err := os.OpenFile(filename,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out_fd.Close()

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
	err = json.Unmarshal(data, res)
	return res, err
}
