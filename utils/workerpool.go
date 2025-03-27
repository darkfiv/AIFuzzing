package utils

import (
	"context"
	"sync"
	"time"
)

// Task 表示一个任务
type Task func() error

// WorkerPool 表示一个工作池
type WorkerPool struct {
	maxWorkers  int
	taskQueue   chan Task
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	workerCount int
	mutex       sync.Mutex
}

// NewWorkerPool 创建一个新的工作池
func NewWorkerPool(maxWorkers int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		maxWorkers: maxWorkers,
		taskQueue:  make(chan Task, maxWorkers*2), // 任务队列缓冲为最大工作者数量的两倍
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start 启动工作池
func (wp *WorkerPool) Start() {
	Info("启动工作池，最大工作者数量: %d", wp.maxWorkers)

	// 启动工作者
	for i := 0; i < wp.maxWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
}

// Stop 停止工作池
func (wp *WorkerPool) Stop() {
	Info("正在停止工作池...")
	
	// 关闭任务队列
	wp.cancel()
	
	// 等待所有工作者完成
	wp.wg.Wait()
	Info("工作池已停止")
}

// Submit 提交一个任务到工作池
func (wp *WorkerPool) Submit(task Task) {
	select {
	case wp.taskQueue <- task:
		// 任务已成功提交到队列
	case <-wp.ctx.Done():
		// 工作池已停止
		Warning("工作池已停止，无法提交任务")
	}
}

// worker 工作者函数
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	wp.incrementWorkerCount()
	Debug("工作者 #%d 已启动", id)

	for {
		select {
		case task, ok := <-wp.taskQueue:
			if !ok {
				Debug("工作者 #%d 的任务队列已关闭", id)
				wp.decrementWorkerCount()
				return
			}

			// 执行任务
			startTime := time.Now()
			err := task()
			duration := time.Since(startTime)

			if err != nil {
				Error("工作者 #%d 的任务执行失败: %v, 耗时: %s", id, err, duration)
			} else {
				Debug("工作者 #%d 的任务执行成功, 耗时: %s", id, duration)
			}

		case <-wp.ctx.Done():
			Debug("工作者 #%d 正在退出", id)
			wp.decrementWorkerCount()
			return
		}
	}
}

// GetActiveWorkerCount 获取当前活动的工作者数量
func (wp *WorkerPool) GetActiveWorkerCount() int {
	wp.mutex.Lock()
	defer wp.mutex.Unlock()
	return wp.workerCount
}

// incrementWorkerCount 增加工作者计数
func (wp *WorkerPool) incrementWorkerCount() {
	wp.mutex.Lock()
	defer wp.mutex.Unlock()
	wp.workerCount++
}

// decrementWorkerCount 减少工作者计数
func (wp *WorkerPool) decrementWorkerCount() {
	wp.mutex.Lock()
	defer wp.mutex.Unlock()
	wp.workerCount--
}

// QueueLength 获取当前任务队列长度
func (wp *WorkerPool) QueueLength() int {
	return len(wp.taskQueue)
}

// WithTimeout 为任务添加超时控制
func WithTimeout(task Task, timeout time.Duration) Task {
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// 使用channel来处理完成和超时
		resultCh := make(chan error, 1)
		go func() {
			resultCh <- task()
		}()

		// 等待任务完成或超时
		select {
		case err := <-resultCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// WithRetry 为任务添加重试机制
func WithRetry(task Task, maxRetries int, retryInterval time.Duration) Task {
	return func() error {
		var lastErr error
		for i := 0; i <= maxRetries; i++ {
			// 执行任务
			err := task()
			if err == nil {
				return nil // 任务成功执行
			}

			lastErr = err
			if i < maxRetries {
				Warning("任务执行失败，将在 %s 后进行第 %d 次重试，错误: %v", retryInterval, i+1, err)
				time.Sleep(retryInterval)
			}
		}
		return lastErr // 返回最后一次错误
	}
} 