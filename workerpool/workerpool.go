package workerpool

import (
	"errors"
	"sync"
)

// WorkerPool 是一个简单的工作池实现
type WorkerPool struct {
	maxWorkers   int
	workers      []*worker
	queue        chan func() error
	wg           sync.WaitGroup
	queueSize    int
	stopped      bool
	stopLock     sync.Mutex
}

// worker 表示一个工作单元
type worker struct {
	pool    *WorkerPool
	jobChan chan func() error
	quit    chan bool
}

// New 创建一个新的工作池
func New(maxWorkers int) *WorkerPool {
	// 默认queue大小为最大工作者数的10倍
	queueSize := maxWorkers * 10
	if queueSize < 10 {
		queueSize = 10
	}

	pool := &WorkerPool{
		maxWorkers: maxWorkers,
		queue:      make(chan func() error, queueSize),
		queueSize:  queueSize,
		stopped:    false,
	}

	// 启动工作者
	pool.workers = make([]*worker, maxWorkers)
	for i := 0; i < maxWorkers; i++ {
		pool.workers[i] = newWorker(pool)
		pool.workers[i].start()
	}

	return pool
}

// newWorker 创建一个新的工作者
func newWorker(pool *WorkerPool) *worker {
	return &worker{
		pool:    pool,
		jobChan: make(chan func() error),
		quit:    make(chan bool),
	}
}

// start 启动工作者
func (w *worker) start() {
	go func() {
		for {
			// 将自己注册到工作池以等待任务
			w.pool.wg.Add(1)
			select {
			case job := <-w.jobChan:
				// 执行任务
				_ = job()
				w.pool.wg.Done()
			case <-w.quit:
				// 收到退出信号
				w.pool.wg.Done()
				return
			}
		}
	}()
}

// stop 停止工作者
func (w *worker) stop() {
	w.quit <- true
}

// Submit 提交一个任务到工作池
func (w *WorkerPool) Submit(job func() error) error {
	w.stopLock.Lock()
	defer w.stopLock.Unlock()

	if w.stopped {
		return errors.New("工作池已停止，无法提交任务")
	}

	select {
	case w.queue <- job:
		// 提交任务到队列
		go func() {
			// 找到一个可用的工作者
			for _, worker := range w.workers {
				select {
				case worker.jobChan <- job:
					return
				default:
					// 这个工作者正忙，尝试下一个
				}
			}
			// 如果没有工作者立即可用，等待队列
			job = <-w.queue
			// 当有工作者可用时，分配任务
			for _, worker := range w.workers {
				select {
				case worker.jobChan <- job:
					return
				default:
					// 这个工作者正忙，尝试下一个
				}
			}
		}()
		return nil
	default:
		// 队列已满
		return errors.New("工作池队列已满，任务被拒绝")
	}
}

// Stop 停止工作池
func (w *WorkerPool) Stop() {
	w.stopLock.Lock()
	defer w.stopLock.Unlock()

	if w.stopped {
		return
	}
	w.stopped = true

	// 停止所有工作者
	for _, worker := range w.workers {
		worker.stop()
	}

	// 等待所有正在执行的任务完成
	w.wg.Wait()

	// 清空队列
	close(w.queue)
} 