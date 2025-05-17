package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	//"runtime"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/sha3"
)

// Keccak256 计算Keccak-256哈希（以太坊标准）
func Keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// generatePrivateKey 生成随机私钥
func generatePrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
}

// privateKeyToAddress 从私钥生成以太坊地址
func privateKeyToAddress(priv *ecdsa.PrivateKey) string {
	pub := priv.Public().(*ecdsa.PublicKey)
	pubBytes := append(pub.X.Bytes(), pub.Y.Bytes()...)
	hash := Keccak256(pubBytes)
	address := hash[12:] // 取最后20字节
	return "0x" + hex.EncodeToString(address)
}

// logResult 记录结果到文件
func logResult(address, privateKey, randomNum string, count int64, duration float64, suffix string) {
	filename := "add" + suffix + ".txt"
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("无法打开日志文件:", err)
		return
	}
	defer file.Close()

	content := fmt.Sprintf("%s\n%s\n%d\n%.2f\n\n",
		address, randomNum, count, duration)
	if _, err := file.WriteString(content); err != nil {
		log.Println("写入日志失败:", err)
	}
}

// printStats 打印统计信息
func printStats(start time.Time, count int64, address, privKey, randomNum string, logToFile bool) {
	elapsed := time.Since(start).Seconds()
	fmt.Printf("用时: %.2f秒\n", elapsed)
	fmt.Printf("总地址数: %d\n", count)
	fmt.Printf("速度: %.2f 地址/秒\n", float64(count)/elapsed)
	fmt.Printf("地址: %s\n", address)
	fmt.Printf("私钥: %s\n", privKey)
	fmt.Printf("随机数: %s\n", randomNum)

	if logToFile {
		logResult(address, privKey, randomNum, count, elapsed, "")
	}
}

// worker 工作协程，生成地址并检查模式
func worker(pattern string, isPrefix bool, found chan struct{}, count *int64, wg chan struct{}) {
	defer func() { <-wg }()

	for {
		select {
		case <-found:
			return
		default:
			// 生成随机数
			randomNum, _ := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))
			randomStr := randomNum.Text(16)

			// 生成私钥
			privKey, _ := generatePrivateKey()
			privBytes := privKey.D.Bytes()
			privHex := hex.EncodeToString(privBytes)

			// 生成地址
			address := privateKeyToAddress(privKey)
			atomic.AddInt64(count, 1)

			// 检查模式匹配
			if len(pattern) > 0 {
				var match bool
				if isPrefix {
					match = len(address) >= len(pattern) && address[:len(pattern)] == pattern
				} else {
					match = len(address) >= len(pattern) && address[len(address)-len(pattern):] == pattern
				}

				if match {
					select {
					case found <- struct{}{}:
						printStats(startTime, *count, address, privHex, randomStr, true)
					default:
					}
					return
				}
			}
		}
	}
}

var startTime time.Time

func main() {
	var pattern string
	var isPrefix bool
	fmt.Print("输入模式 (前缀加p/如p123, 后缀直接输入/如123): ")
	fmt.Scanln(&pattern)

	// 判断是否是前缀模式
	if len(pattern) > 1 && pattern[0] == 'p' {
		isPrefix = true
		pattern = pattern[1:]
	}

	startTime = time.Now()
	var count int64
	found := make(chan struct{})
	workerCount := 8//runtime.NumCPU() * 1 // 使用2倍CPU核心数的worker
	wg := make(chan struct{}, workerCount)

	fmt.Printf("启动 %d 个worker...\n", workerCount)

	// 启动worker
	for i := 0; i < workerCount; i++ {
		wg <- struct{}{}
		go worker(pattern, isPrefix, found, &count, wg)
	}

	// 等待找到匹配
	<-found
	close(found)
}
