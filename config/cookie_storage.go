package config

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gogf/gf/v2/frame/g"
)

// CookieData Cookie 数据结构
type CookieData struct {
	Secure1PSID   string    `json:"secure_1psid"`
	Secure1PSIDTS string    `json:"secure_1psidts"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// CookieStorage Cookie 存储接口
// 以后可以实现数据库存储
type CookieStorage interface {
	// Load 加载 Cookie
	Load(ctx context.Context) (*CookieData, error)
	// Save 保存 Cookie
	Save(ctx context.Context, data *CookieData) error
}

// FileCookieStorage 文件存储实现
type FileCookieStorage struct {
	FilePath string
	mutex    sync.RWMutex
}

// NewFileCookieStorage 创建文件存储
func NewFileCookieStorage(filePath string) *FileCookieStorage {
	if filePath == "" {
		filePath = "./cookies/cookie_config.json"
	}
	return &FileCookieStorage{
		FilePath: filePath,
	}
}

// Load 从文件加载 Cookie
func (s *FileCookieStorage) Load(ctx context.Context) (*CookieData, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	data, err := ioutil.ReadFile(s.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // 文件不存在,返回 nil
		}
		return nil, fmt.Errorf("读取 Cookie 配置文件失败: %w", err)
	}

	var cookieData CookieData
	if err := json.Unmarshal(data, &cookieData); err != nil {
		return nil, fmt.Errorf("解析 Cookie 配置文件失败: %w", err)
	}

	return &cookieData, nil
}

// Save 保存 Cookie 到文件
func (s *FileCookieStorage) Save(ctx context.Context, data *CookieData) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 确保目录存在
	dir := filepath.Dir(s.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 设置更新时间
	data.UpdatedAt = time.Now()

	// 序列化为 JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 Cookie 数据失败: %w", err)
	}

	// 写入文件
	if err := ioutil.WriteFile(s.FilePath, jsonData, 0644); err != nil {
		return fmt.Errorf("写入 Cookie 配置文件失败: %w", err)
	}

	g.Log().Info(ctx, "Cookie 已保存到文件:", s.FilePath)
	return nil
}

// DatabaseCookieStorage 数据库存储实现 (占位符,以后实现)
type DatabaseCookieStorage struct {
	// TODO: 添加数据库连接等字段
}

// NewDatabaseCookieStorage 创建数据库存储
func NewDatabaseCookieStorage() *DatabaseCookieStorage {
	return &DatabaseCookieStorage{}
}

// Load 从数据库加载 Cookie
func (s *DatabaseCookieStorage) Load(ctx context.Context) (*CookieData, error) {
	// TODO: 实现数据库读取
	// 示例:
	// var cookieData CookieData
	// err := g.DB().Model("cookies").Where("id", 1).Scan(&cookieData)
	// return &cookieData, err
	return nil, fmt.Errorf("数据库存储尚未实现")
}

// Save 保存 Cookie 到数据库
func (s *DatabaseCookieStorage) Save(ctx context.Context, data *CookieData) error {
	// TODO: 实现数据库写入
	// 示例:
	// _, err := g.DB().Model("cookies").Data(data).Save()
	// return err
	return fmt.Errorf("数据库存储尚未实现")
}

// 全局存储实例
var (
	cookieStorage     CookieStorage
	cookieStorageMutex sync.RWMutex
)

// InitCookieStorage 初始化 Cookie 存储
func InitCookieStorage(storage CookieStorage) {
	cookieStorageMutex.Lock()
	defer cookieStorageMutex.Unlock()
	cookieStorage = storage
}

// GetCookieStorage 获取 Cookie 存储实例
func GetCookieStorage() CookieStorage {
	cookieStorageMutex.RLock()
	defer cookieStorageMutex.RUnlock()
	return cookieStorage
}

// SaveCookieToStorage 保存当前 Cookie 到存储
func SaveCookieToStorage(ctx context.Context) error {
	storage := GetCookieStorage()
	if storage == nil {
		return fmt.Errorf("Cookie 存储未初始化")
	}

	cookieMutex.RLock()
	data := &CookieData{
		Secure1PSID:   Secure1PSID,
		Secure1PSIDTS: Secure1PSIDTS,
	}
	cookieMutex.RUnlock()

	return storage.Save(ctx, data)
}

// LoadCookieFromStorage 从存储加载 Cookie
func LoadCookieFromStorage(ctx context.Context) error {
	storage := GetCookieStorage()
	if storage == nil {
		return fmt.Errorf("Cookie 存储未初始化")
	}

	data, err := storage.Load(ctx)
	if err != nil {
		return err
	}

	if data == nil {
		return nil // 没有存储的数据
	}

	cookieMutex.Lock()
	Secure1PSID = data.Secure1PSID
	Secure1PSIDTS = data.Secure1PSIDTS
	cookieMutex.Unlock()

	g.Log().Info(ctx, "从存储加载 Cookie 成功, 更新时间:", data.UpdatedAt)
	return nil
}
