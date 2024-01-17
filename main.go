package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc64"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"smtool/postrs"

	"github.com/davecgh/go-spew/spew"
	"github.com/spacemeshos/go-scale"
	"github.com/spacemeshos/go-spacemesh/codec"
	"github.com/spacemeshos/go-spacemesh/common/types"
	"github.com/spacemeshos/post/config"
	"github.com/spacemeshos/post/initialization"
	"github.com/spacemeshos/post/oracle"
	"github.com/spacemeshos/post/shared"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var ErrNonceExists = errors.New("nonce is in postdata_metadata.json")

type params struct {
	nodeId          []byte
	commitmentAtxId []byte
	labelsPerUnit   uint64
	numUnits        uint32
	maxFileSize     uint64

	dataDir           string
	provider          uint32
	commitment        []byte
	powDifficultyFunc func(uint64) []byte

	lastPosition atomic.Pointer[uint64]
	nonce        atomic.Pointer[uint64]
	nonceValue   atomic.Pointer[[]byte]

	logger *zap.Logger
}

func CPUProviderID() uint32 {
	return postrs.CPUProviderID()
}

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

	genonce := &cobra.Command{
		Use:   "genonce",
		Short: "Execute generate nonce",
		Long:  "Generate nonce for matedata.json",
		Run: func(cmd *cobra.Command, args []string) {
			path, _ := cmd.Flags().GetString("path")
			// 加载postdata_metadata.json
			logLevel, _ := cmd.Flags().GetInt8("logLevel")
			provider, _ := cmd.Flags().GetUint32("provider")
			params, err := newParams(path, logLevel, provider)
			if err != nil {
				if err == ErrNonceExists {
					fmt.Println("nonce is exists")
					return
				}
				fmt.Println("failed to new params: ", err.Error())
				return
			}
			if err = params.generateNonce(); err != nil {
				fmt.Println("failed to generate nonce: ", err.Error())
				return
			}
		},
	}

	genonce.Flags().Uint32("provider", postrs.CPUProviderID(), "provider id")
	genonce.Flags().Int8("logLevel", int8(zapcore.InfoLevel), "log level")
	genonce.Flags().String("path", "", "node data dir")
	rootCmd.AddCommand(genonce)

	// 运行根命令
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func newParams(path string, logLevel int8, provider uint32) (params, error) {
	filepath := filepath.Join(path)
	if !fileExists(filepath) {
		return params{}, fmt.Errorf("postdata_metedata does not exist in directory")
	}
	metadata, err := initialization.LoadMetadata(filepath)
	if err != nil {
		return params{}, err
	}
	if metadata.Nonce != nil {
		return params{}, ErrNonceExists
	}
	zapCfg := zap.Config{
		Level:    zap.NewAtomicLevelAt(zapcore.Level(logLevel)),
		Encoding: "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "T",
			LevelKey:       "L",
			NameKey:        "N",
			MessageKey:     "M",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := zapCfg.Build()
	if err != nil {
		log.Fatalln("failed to initialize zap logger:", err)
	}
	return params{
		nodeId:          metadata.NodeId,
		commitmentAtxId: metadata.CommitmentAtxId,
		labelsPerUnit:   metadata.LabelsPerUnit,
		numUnits:        metadata.NumUnits,
		maxFileSize:     metadata.MaxFileSize,
		commitment:      oracle.CommitmentBytes(metadata.NodeId, metadata.CommitmentAtxId),
		logger:          logger,
		provider:        provider,
		dataDir:         path,
	}, nil
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil || os.IsExist(err)
}

func (p *params) generateNonce() error {
	scrypt := config.DefaultLabelParams()
	batchSize := uint64(config.DefaultComputeBatchSize)
	// 读matedata
	numLabels := uint64(p.numUnits) * p.labelsPerUnit
	p.powDifficultyFunc = shared.PowDifficulty
	difficulty := p.powDifficultyFunc(numLabels)

	wo, err := oracle.New(
		oracle.WithProviderID(&p.provider),
		oracle.WithCommitment(p.commitment),
		oracle.WithVRFDifficulty(difficulty),
		oracle.WithScryptParams(scrypt),
		oracle.WithLogger(p.logger),
	)
	if err != nil {
		return err
	}
	defer wo.Close()

	p.logger.Info("generateNonce: no nonce found while computing labels, continue initializing", zap.String("datadir", p.dataDir))
	if p.lastPosition.Load() == nil || *p.lastPosition.Load() < numLabels {
		lastPos := numLabels
		p.lastPosition.Store(&lastPos)
	}

	// continue searching for a nonce
	defer p.saveMetadata()

	start := time.Now()
	for i := uint64(0); i < math.MaxUint64; i += batchSize {
		lastPos := i
		p.lastPosition.Store(&lastPos)

		p.logger.Debug("generateNonce: continue looking for a nonce",
			zap.Uint64("startPosition", i),
			zap.Uint64("batchSize", batchSize),
		)

		res, err := wo.Positions(i, i+batchSize-1)
		if err != nil {
			return err
		}
		if res.Nonce != nil {
			p.logger.Debug("generateNonce: found nonce",
				zap.Uint64("nonce", *res.Nonce),
			)

			p.nonce.Store(res.Nonce)
			break
		}
	}
	elapsed := time.Since(start)
	p.logger.Info("generateNonce: finish find nonce", zap.String("spendtime", elapsed.String()))
	return nil
}

func (p *params) saveMetadata() error {
	v := shared.PostMetadata{
		NodeId:          p.nodeId,
		CommitmentAtxId: p.commitmentAtxId,
		LabelsPerUnit:   p.labelsPerUnit,
		NumUnits:        p.numUnits,
		MaxFileSize:     p.maxFileSize,
		Nonce:           p.nonce.Load(),
		LastPosition:    p.lastPosition.Load(),
	}
	if p.nonceValue.Load() != nil {
		v.NonceValue = *p.nonceValue.Load()
	}
	return initialization.SaveMetadata(p.dataDir, &v)
}
