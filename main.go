package main

import (
	"encoding/binary"
	"fmt"
	"hash/crc64"
	"io"
	"log"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/spacemeshos/go-scale"
	"github.com/spacemeshos/go-spacemesh/codec"
	"github.com/spacemeshos/go-spacemesh/common/types"
	"github.com/spf13/cobra"
)

func load(filename string, dst scale.Decodable) error {
	data, err := read(filename)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	if err := codec.Decode(data, dst); err != nil {
		return fmt.Errorf("decoding: %w", err)
	}
	return nil
}

func read(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file %s: %w", path, err)
	}
	defer file.Close()

	fInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info %s: %w", path, err)
	}
	if fInfo.Size() < crc64.Size {
		return nil, fmt.Errorf("file %s is too small", path)
	}

	data := make([]byte, fInfo.Size()-crc64.Size)
	checksum := crc64.New(crc64.MakeTable(crc64.ISO))
	if _, err := io.TeeReader(file, checksum).Read(data); err != nil {
		return nil, fmt.Errorf("read file %s: %w", path, err)
	}

	saved := make([]byte, crc64.Size)
	if _, err := file.Read(saved); err != nil {
		return nil, fmt.Errorf("read checksum %s: %w", path, err)
	}

	savedChecksum := binary.BigEndian.Uint64(saved)

	if savedChecksum != checksum.Sum64() {
		return nil, fmt.Errorf("wrong checksum 0x%X, computed 0x%X", savedChecksum, checksum.Sum64())
	}

	return data, nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "smtool",
		Short: "Smtool is a spacemesh CLI tool box",
		Long:  "Smtool is a spacemesh CLI tool box.",
	}

	// 添加一个名为 "command1" 的子命令
	parsePost := &cobra.Command{
		Use:   "parsePost",
		Short: "Execute parsePost",
		Long:  "parsePost is decode post.bin to struct",
		Run: func(cmd *cobra.Command, args []string) {
			var post types.Post
			path, _ := cmd.Flags().GetString("path")
			if err := load(path, &post); err != nil {
				fmt.Println("loading post: %w", err)
			}
			spew.Dump(post)
		},
	}

	parsePost.Flags().String("path", "", "post.bin absolute path")
	rootCmd.AddCommand(parsePost)

	// 运行根命令
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
